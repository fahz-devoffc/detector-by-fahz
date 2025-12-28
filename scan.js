export default async function handler(req,res){
try{
const submit=await fetch("https://www.virustotal.com/api/v3/urls",{
method:"POST",
headers:{
"x-apikey":process.env.VT_API_KEY,
"Content-Type":"application/x-www-form-urlencoded"
},
body:new URLSearchParams({url:req.body.value})
});
const s=await submit.json();
await new Promise(r=>setTimeout(r,4000));
const report=await fetch(`https://www.virustotal.com/api/v3/analyses/${s.data.id}`,{
headers:{"x-apikey":process.env.VT_API_KEY}
});
const d=await report.json();
const st=d.data.attributes.stats;
res.json(st);
}catch{res.status(500).json({error:"scan error"})}
}