


// All FPR Utils come here

function decorate_fpr_url(base_url){

    new_url = base_url;
    if(base_url.includes('?')){
        new_url += `&`;
    } else {
        new_url += `?`;
    }

    new_url += `api_key=${FPR_API_KEY}`;

    return new_url;
}

function decorate_fpr_url_with_session(base_url, sid){
    
    new_url = decorate_fpr_url(base_url);
    new_url += `&sid=${sid}`;

    return new_url;
}

function show_fpr_error(document, data){
    document.getElementById(
        "err-msg"
    ).innerHTML = `<div class="err-msg">${error_codes[data.error_code]}</div>`;
}