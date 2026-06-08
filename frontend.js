async function check_user(username,password){
    let response = await fetch('http://127.0.0.1:8000/signin', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({username:username,Secretkey:password})
    });

    let data = await response.json()        
    return data
    }
async function get_token(authtoken){
    let response = await fetch('http:127.0.0.1:8000/dashboard',{
        method : 'GET',
        headers : {'Authorization':'Bearer ${authtoken}'},
        
    })

    let data = await response.json();
    return data

}
