/* Pure browser/Node helpers. No generation, uploads, execution or model calls. */
(function (root) {
  'use strict';
  const MAX_PROFILE_BYTES = 1024 * 1024;
  function validate(value, schema, path = 'profile') {
    if (schema.not && Object.keys(schema.not).length === 0) throw Error(`${path}: trường này đã bị loại khỏi cấu trúc chuẩn.`);
    const type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    const actual = type === 'object' ? 'object' : type;
    const expected = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (schema.type && !expected.includes(actual)) throw Error(`${path}: kiểu dữ liệu phải là ${expected.join(' / ')}.`);
    if (schema.enum && !schema.enum.includes(value)) throw Error(`${path}: giá trị không được phép.`);
    if (actual === 'object') {
      for (const key of schema.required || []) if (!Object.prototype.hasOwnProperty.call(value, key)) throw Error(`${path}: thiếu trường ${key}.`);
      for (const [key, entry] of Object.entries(value)) {
        if (Object.prototype.hasOwnProperty.call(schema.properties || {}, key)) validate(entry, schema.properties[key], `${path}.${key}`);
        else if (schema.additionalProperties === false) throw Error(`${path}: trường ${key} nằm ngoài cấu trúc chuẩn.`);
      }
    }
    if (Array.isArray(value)) {
      if (value.length < (schema.minItems || 0)) throw Error(`${path}: chưa đủ phần tử.`);
      value.forEach((entry, i) => validate(entry, schema.items || {}, `${path}[${i}]`));
    }
    if (typeof value === 'string' && value.trim().length < (schema.minLength || 0)) throw Error(`${path}: không được để trống.`);
  }
  function validateProfile(value, schema) {
    const copy = JSON.parse(JSON.stringify(value));
    if (copy && Array.isArray(copy.services)) {
      const legacy = copy.services.filter(s => s.kind !== 'web' && s.url && Number.isInteger(s.http_status));
      const groups = new Map();
      for (const row of legacy) {
        let url; try { url = new URL(row.url); } catch (_) { continue; }
        if (!['http:', 'https:'].includes(url.protocol) || row.http_status < 200 || row.http_status > 599 || row.http_status === 400 || row.error) continue;
        const base = url.origin + '/';
        if (!groups.has(base)) groups.set(base, {kind:'web',name:url.protocol.slice(0,-1).toUpperCase(),url:base,status:'observed',evidence_ref:'#/services',applications:[]});
        const name = row.http_status < 300 ? (row.application_hint === 'DVWA' || /\bdvwa\b|damn vulnerable web application/i.test(row.title || '') ? 'DVWA' : row.application_hint === 'XAMPP' || /welcome to xampp/i.test(row.title || '') ? 'XAMPP' : null) : null;
        if (!name) continue;
        const match = url.pathname.match(/\/(dvwa|dashboard)(?:\/|$)/i);
        const path = match ? url.pathname.slice(0,match.index + match[0].length).replace(/\/$/,'') + '/' : url.pathname.slice(0,url.pathname.lastIndexOf('/') + 1);
        const appBase = url.origin + path;
        const group = groups.get(base);
        if (!group.applications.some(a => a.name === name && a.base_url === appBase)) group.applications.push({name,base_url:appBase,application_identified:true,session_ready:null,current_security_level:null,version:null,evidence_ref:'#/services'});
      }
      copy.services = copy.services.filter(s => !legacy.includes(s)).concat([...groups.values()]);
    }
    validate(copy, schema);
    return copy;
  }
  async function readProfile(file, schema) {
    if (!file || !/\.json$/i.test(file.name)) throw Error('Chọn file Target Profile có đuôi .json.');
    if (file.size > MAX_PROFILE_BYTES) throw Error('File lớn hơn 1 MB. Vui lòng chọn hồ sơ nhỏ hơn.');
    let value;
    try { value = JSON.parse(await file.text()); }
    catch (_) { throw Error('Không đọc được JSON. Kiểm tra nội dung file Target Profile.'); }
    return validateProfile(value, schema);
  }
  function searchable(text) {
    return String(text).normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D').toLowerCase();
  }
  function filterScenarios(items, query = '', family = 'all', scope = 'all') {
    const needle = searchable(query.trim());
    return items.filter(item => (family === 'all' || item.family === family) &&
      (scope === 'all' || item.scope.includes(scope)) &&
      (!needle || searchable([item.name, item.description, item.id, item.file, ...item.abilities].join(' ')).includes(needle)));
  }
  function preview(source) {
    // Return the exact existing YAML; request/profile are not used to fake AI output.
    const base = source.file.split('/').pop().replace(/\.(ya?ml)$/i, '').replace(/[^a-zA-Z0-9_-]/g, '_');
    return { yaml: source.yaml, filename: base + '.sample.yml', steps: source.abilities.length };
  }
  const exported = { MAX_PROFILE_BYTES, validateProfile, readProfile, filterScenarios, preview };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  else root.ScenarioCore = exported;
})(typeof globalThis !== 'undefined' ? globalThis : this);
