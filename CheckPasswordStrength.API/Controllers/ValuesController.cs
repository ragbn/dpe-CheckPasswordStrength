using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Formatting;
using System.IO;

namespace CheckPasswordStrength.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly IDetermineStrengthService _pwdStrengthService;
        

        public ValuesController (IDetermineStrengthService pwdStrengthService)
        {
            this._pwdStrengthService = pwdStrengthService;
            
        }

        // GET api/values
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values
        [HttpPost]
        public async Task<string> Checkpassword()
        {
            
            //  HttpContent content = Request.conte
            using (StreamReader stream = new StreamReader(HttpContext.Request.Body))
            {
                string body = stream.ReadToEnd();
                return await _pwdStrengthService.CheckStrength(body);
               
            }
           
        }

        ////// GET api/values/5
        //[HttpGet("{password}")]
        //public async Task<ActionResult<string>> Checkpassword(string password)
        //{
        //    return await _pwdStrengthService.CheckStrength(password);
        //}

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
