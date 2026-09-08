-- mx report-only exporter: classifications are Bayes predictions, not verified
-- ground truth. Action and total score never determine classification.
local rspamd_config = rspamd_config
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local rspamd_util = require "rspamd_util"
local bit = require "bit"

local output = '/var/lib/rspamd/tlsgate/verdicts.jsonl'
local instance = 'mx-public-smtp'
local spam_symbol = 'BAYES_SPAM'
local ham_symbol = 'BAYES_HAM'
local write_failures = 0

local function report_write_failure(task, err)
  write_failures = write_failures + 1
  -- Log the first failure and then at powers of two, bounding log volume while
  -- keeping a persistent failure visible.
  if write_failures == 1 or bit.band(write_failures, write_failures - 1) == 0 then
    rspamd_logger.errx(task, 'tlsgate verdict export failed (%s failures): %s',
        write_failures, err or 'unknown error')
  end
end

rspamd_config:register_symbol({
  name = 'TLSGATE_VERDICT_EXPORT',
  type = 'idempotent',
  flags = 'ignore_passthrough',
  callback = function(task)
    local queue_id = task:get_queue_id()
    if not queue_id or queue_id == '' then return end
    local metric = task:get_metric_result() or {}
    local symbols, names = task:get_symbols_all() or {}, {}
    local classification = 'unknown'
    local saw_spam, saw_ham = false, false
    for _, symbol in ipairs(symbols) do
      local name = symbol.name
      names[#names + 1] = name
      if name == spam_symbol then saw_spam = true end
      if name == ham_symbol then saw_ham = true end
    end
    if saw_spam and not saw_ham then classification = 'spam' end
    if saw_ham and not saw_spam then classification = 'ham' end
    table.sort(names)
    local now = rspamd_util.get_time()
    local record = {
      timestamp = os.date('!%Y-%m-%dT%H:%M:%S', math.floor(now)) ..
          string.format('.%06dZ', math.floor((now % 1) * 1000000)),
      instance = instance,
      queue_id = queue_id, classification = classification,
      score = metric.score or 0, action = metric.action or 'unknown',
      symbols = names,
    }
    local f, open_err = io.open(output, 'a')
    if not f then report_write_failure(task, open_err or 'open failed'); return end
    local line = ucl.to_format(record, 'json-compact') .. '\n'
    local ok, err = f:write(line)
    local close_ok, close_err = f:close()
    if not ok or not close_ok then
      report_write_failure(task, err or close_err)
    end
  end,
})
