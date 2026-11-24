"""Typed boundaries. Facts enter through tool evidence, never through model prose."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class NoArguments(StrictModel):
    pass


class WebArguments(StrictModel):
    source: Literal['configured', 'discovered']


class Listener(StrictModel):
    LocalAddress: str
    LocalPort: int = Field(ge=1, le=65535)
    OwningProcess: int = Field(ge=0)


class ListenerProcess(StrictModel):
    pid: int = Field(ge=0)
    name: str
    executable_path: str | None = None


class WindowsService(StrictModel):
    name: str
    display_name: str
    state: str
    process_id: int | None = None


class EndpointData(StrictModel):
    os_name: str
    os_version: str
    architecture: str
    hostname: str
    username: str
    is_elevated: bool
    powershell_version: str
    collected_at: str
    processes: list[ListenerProcess] = Field(default_factory=list)
    listener_count: int | None = None
    service_count: int | None = None
    listeners: list[Listener]
    services: list[WindowsService]
    telemetry_observations: dict[str, dict] = Field(default_factory=dict)
    limitations: list[str]


class EndpointEvidence(StrictModel):
    tool: Literal['get_endpoint_info']
    target: str
    status: Literal['ok']
    data: EndpointData
    evidence: list[str]
    error: None


class OperatingSystem(StrictModel):
    name: str | None
    version: str | None
    architecture: str | None
    hostname: str | None
    status: Literal['observed', 'reported_by_caldera', 'unknown']


class Capabilities(StrictModel):
    sandcat_online: bool | None
    powershell_ready: bool | None
    admin_ready: bool | None
    web_runner_ready: bool | None
    web_reachable: bool | None
    application_identified: bool | None = None
    dvwa_session_ready: bool | None = None


class Telemetry(StrictModel):
    process_events: bool | None = None
    network_events: bool | None = None
    web_access_logs: bool | None = None
    wazuh_ingestion: bool | None = None


class WebApplication(StrictModel):
    name: str
    base_url: str
    application_identified: Literal[True]
    session_ready: bool | None = None
    current_security_level: Literal['low', 'medium', 'high', 'impossible'] | None = None
    version: None = None
    evidence_ref: str
    authentication_ref: str | None = None
    modules_ref: str | None = None


class Service(StrictModel):
    name: str
    kind: Literal['web', 'endpoint'] | None = None
    applications: list[WebApplication] | None = None
    evidence_ref: str | None = None
    listeners: list[Listener] | None = None
    processes: list[ListenerProcess] | None = None
    service_name: str | None = None
    state: str | None = None
    paw: str | None = None
    privilege: str | None = None
    status: str
    url: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    server: str | None = None
    title: str | None = None
    application_hint: str | None = None
    session_ready: bool | None = None
    current_security_level: Literal['low', 'medium', 'high', 'impossible'] | None = None


class TargetProfile(StrictModel):
    id: str
    os: OperatingSystem
    address: str
    services: list[Service]
    capabilities: Capabilities
    telemetry: Telemetry


TOOL_ARGUMENTS = {
    'collect_endpoint': NoArguments,
    'probe_web': WebArguments,
    'probe_dvwa': WebArguments,
    'inspect_dvwa_modules': NoArguments,
    'finish_survey': NoArguments,
}

DESCRIPTIONS = {
    'collect_endpoint': 'Read Windows OS, identity, privilege, listeners and service inventory through CALDERA/Sandcat. One attempt. No configuration changes.',
    'probe_web': 'Read HTTP on configured ports or listener ports observed by collect_endpoint. Discovered source requires endpoint evidence. Same target only; bounded GETs. Each source once.',
    'probe_dvwa': 'Probe administrator-configured DVWA paths on configured or observed listener ports. When administrator-enabled, verifies login and reads security level without changing it. Each source once.',
    'inspect_dvwa_modules': 'After verified DVWA login, read discovered module directory pages and form metadata. GET only after login; never submit attack forms. One attempt.',
    'finish_survey': 'Stop collecting and let deterministic code build the profile from evidence. Cannot supply facts. Missing requested checks are reported as partial.',
}


def tool_definitions(request):
    names = ['collect_endpoint', 'finish_survey']
    if 'web' in request['survey_scope']:
        names.append('probe_web')
        if 'dvwa' in request.get('web_checks', []):
            names.extend(['probe_dvwa', 'inspect_dvwa_modules'])
    return [{'type': 'function', 'function': {
        'name': name, 'description': DESCRIPTIONS[name],
        'parameters': TOOL_ARGUMENTS[name].model_json_schema(), 'strict': True,
    }} for name in names]
