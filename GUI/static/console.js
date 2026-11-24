/* Console preferences and read-only catalog explorer. */
(() => {
  'use strict';
  const el=id=>document.getElementById(id);
  const apply=theme=>{document.documentElement.dataset.theme=theme;const dark=theme==='dark';el('theme-toggle').textContent=dark?'☀ Giao diện sáng':'☾ Giao diện tối';el('theme-toggle').setAttribute('aria-pressed',String(dark));};
  let theme='light';try {theme=localStorage.getItem('soc-theme')==='dark'?'dark':'light';}catch(_){}apply(theme);
  el('theme-toggle').onclick=()=>{const next=document.documentElement.dataset.theme==='dark'?'light':'dark';apply(next);try{localStorage.setItem('soc-theme',next);}catch(_){}};
  let items=[],page=1;const size=20;
  const text=(tag,value,cls)=>{const n=document.createElement(tag);n.textContent=value;if(cls)n.className=cls;return n;};
  function render(){
    const q=el('ability-search').value.trim().toLocaleLowerCase();
    const found=items.filter(x=>[x.name,x.ability_id,x.description,x.tactic,x.technique_id,...x.executors.map(e=>e.platform+' '+e.name)].join(' ').toLocaleLowerCase().includes(q));
    const pages=Math.max(1,Math.ceil(found.length/size));page=Math.min(page,pages);
    el('ability-count').textContent=`${found.length.toLocaleString('vi-VN')} bản ghi ability · ${items.length.toLocaleString('vi-VN')} trong catalog`;
    el('ability-page').textContent=`Trang ${page} / ${pages}`;el('ability-prev').disabled=page===1;el('ability-next').disabled=page===pages;
    el('ability-list').replaceChildren();
    if(!found.length)el('ability-list').append(text('p','Không tìm thấy ability. Thử từ khóa khác.','empty-state'));
    for(const item of found.slice((page-1)*size,page*size)){
      const b=text('button','', 'ability-row');b.type='button';
      const left=text('span','');left.append(text('strong',item.name||item.ability_id),text('small',item.technique_id+' · '+(item.tactic||'Chưa phân loại')));
      b.append(left,text('span',[...new Set(item.executors.map(e=>e.platform+' / '+e.name))].join(', ')||'Chưa có executor','ability-platform'));
      b.onclick=()=>{el('ability-name').textContent=item.name||item.ability_id;el('ability-description').textContent=item.description||'Chưa có mô tả.';el('ability-detail').textContent=JSON.stringify({id:item.ability_id,record:item.record_id,technique:item.technique_id,technique_name:item.technique_name,tactic:item.tactic,executors:item.executors,privilege:item.privilege,source:item.source_kind,review:item.review_status},null,2);el('ability-dialog').showModal();};el('ability-list').append(b);
    }
  }
  el('ability-search').oninput=()=>{page=1;render();};el('ability-prev').onclick=()=>{page--;render();};el('ability-next').onclick=()=>{page++;render();};el('ability-close').onclick=()=>el('ability-dialog').close();
  fetch('/api/abilities').then(async r=>{if(!r.ok)throw Error('Không tải được kho ability. Hãy tải lại trang.');return r.json();}).then(d=>{items=d.items;render();}).catch(e=>{el('ability-count').textContent=e.message;el('ability-prev').disabled=el('ability-next').disabled=true;});
})();
