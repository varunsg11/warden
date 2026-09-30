@echo off
setlocal EnableDelayedExpansion
rem Real-model AgentDojo runs (gpt-4o-mini): none, task, task+prov -- one at a time
rem (the OpenAI account's tokens-per-minute limit) and resumable: episodes already
rem logged are reused, so re-running after an interruption never pays twice.
rem Needs OPENAI_API_KEY in .env and the .venv-agentdojo venv (see README.md here).
rem Progress: results\agentdojo\logs\realrun.log
cd /d "%~dp0..\.."
set PY=.venv-agentdojo\Scripts\python.exe
set LOG=results\agentdojo\logs\realrun.log
if not exist results\agentdojo\logs mkdir results\agentdojo\logs
for %%C in (none task task+prov) do (
  echo ##### START %%C %DATE% %TIME%>> %LOG%
  %PY% -u experiments\agentdojo\run.py --model gpt-4o-mini-2024-07-18 --config %%C --resume >> %LOG% 2>&1
  echo ##### END %%C exit=!ERRORLEVEL! %DATE% %TIME%>> %LOG%
)
%PY% experiments\agentdojo\summarize.py >> %LOG% 2>&1
echo ##### ALL DONE -- see results\agentdojo\README.md>> %LOG%
