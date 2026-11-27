"""Local deployment helper; credentials remain in private files, never argv/output."""
import base64,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PRIVATE=Path.home()/'.config/datn-telemetry'


def windows(script,timeout=40):
    credential=PRIVATE/'windows.json'
    username=json.loads(credential.read_text())['username']
    env=dict(os.environ,SSH_ASKPASS=str(ROOT/'engine/ssh_askpass.py'),SSH_ASKPASS_REQUIRE='force',DISPLAY='soc-telemetry:0',SURVEY_SSH_CREDENTIAL_FILE=str(credential))
    args=['ssh','-T','-F','/dev/null','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts'),'-o','ConnectTimeout=5','-o','NumberOfPasswordPrompts=1','-o','PreferredAuthentications=password',username+'@192.168.1.150','powershell.exe -NoProfile -NonInteractive -EncodedCommand '+base64.b64encode("& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))))".encode('utf-16le')).decode()]
    result=subprocess.run(args,input=base64.b64encode(script.encode()),capture_output=True,env=env,timeout=timeout)
    if result.returncode:raise RuntimeError('Host command failed; exit '+str(result.returncode))
    return result.stdout.decode('utf-8-sig').strip()


def ubuntu(script,timeout=30):
    password=json.loads((PRIVATE/'local.json').read_text())['password']
    result=subprocess.run(['sudo','-S','-p','','python3','-c',script],input=(password+'\n').encode(),capture_output=True,timeout=timeout)
    if result.returncode:raise RuntimeError('Local privileged command failed; exit '+str(result.returncode))
    return result.stdout.decode().strip()
