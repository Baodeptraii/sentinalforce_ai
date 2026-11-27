"""Conservative source-level intent evidence. Never executes or generates commands."""
import re
from .selection import plain

INTENT_VERSION = 2
SHELLS = {'psh':'powershell','powershell':'powershell','powershell.exe':'powershell',
          'pwsh':'pwsh','pwsh.exe':'pwsh','cmd':'cmd','cmd.exe':'cmd','sh':'sh','bash':'bash'}
PROCESS = r'(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|bash|sh|python(?:3|\.exe)?|[a-z0-9_.-]+\.exe)'


def process_name(value):
    name=re.split(r'[/\\]',value.strip(' \t\"\x27'))[-1].lower()
    return SHELLS.get(name,name)


def process_requirement(behavior):
    text=plain(behavior.get('source_quote',''))
    pattern=(r'\b(?P<parent>'+PROCESS+r')\s*(?:(?:doc hai|malicious|suspicious)\s+)?'
             r'(?:spawn(?:s|ed|ing)?|launch(?:es|ed|ing)?|start(?:s|ed|ing)?|sinh(?: ra)?|tao(?: ra)?|khoi tao|->|→)\s*'
             r'(?:(?:a |an )?(?:child process|child|process|tien trinh)\s+)?(?P<child>'+PROCESS+r')\b')
    matches=list(re.finditer(pattern,text,re.I))
    match=matches[0] if len(matches)==1 else None
    return {'parent':process_name(match['parent']),'child':process_name(match['child'])} if match else None


def statements(command):
    """Split supported code at real statement/block boundaries, retaining quoted data.

    Abstain on here strings/block comments/subexpressions rather than certifying
    command names merely printed, assigned as data, or passed to another parent.
    """
    if any(s in command for s in ("@'",'@"','<#','$(')):return []
    result=[];start=0;quote=None;comment=False;i=0
    while i<len(command):
        char=command[i]
        if comment:
            if char=='\n':comment=False;start=i+1
            i+=1;continue
        if quote:
            if char=='`' and quote=='"':i+=2;continue
            if char==quote:
                if quote=="'" and command[i:i+2]=="''":i+=2;continue
                quote=None
            i+=1;continue
        if char in ('"',"'"):quote=char
        elif char=='#' and command[i:i+2]!='#{':
            if command[start:i].strip():result.append(command[start:i].strip())
            comment=True
        elif char in ';\n{}':
            if command[start:i].strip():result.append(command[start:i].strip())
            start=i+1
        elif char=='`':i+=2;continue
        i+=1
    if not quote and not comment and command[start:].strip():result.append(command[start:].strip())
    return result


def _head(statement):
    return re.sub(r'^\$[a-zA-Z_][\w]*\s*=\s*','',statement).strip()


def process_evidence(command,executor,required):
    parent=SHELLS.get(executor.lower(),executor.lower())
    if parent!=required['parent']:return None
    for statement in statements(command):
        text=_head(statement)
        # Bare quoted strings are data; & and Start-Process can launch literal filenames.
        start=re.match(r'''(?i)^Start-Process\s+(?:-FilePath\s+)?(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;]+))''',text)
        invoke=re.match(r'''^&\s*(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;]+))''',text)
        bare=re.match(r'^([A-Za-z_][\w.:-]*(?:\\[^\s;]+)?)\b',text)
        token=next((g for g in (start or invoke).groups() if g),None) if start or invoke else bare.group(1) if bare else None
        if token and process_name(token)==required['child']:
            return {'parent':parent,'child':required['child'],'method':'literal_launcher_with_executor_parent',
                    'source_fragment':statement,'execution_observed':False}
    return None

