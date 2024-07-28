using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebApiLogin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InterfaceController : ControllerBase
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _config;

        public InterfaceController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _config = configuration;
        }

        // GET: api/<InterfaceController>
        [Authorize]
        [HttpGet]
        public IActionResult Get()
        {
            var values = new List<string> { "Value1", "Value2", "Value3" };
            return Ok(values);
        }
        public class api_login
        {

            public string UserName { get; set; }
            public string Password { get; set; }

        }
        public class AuthenticationResult
        {
            public bool HasError { get; set; }
            public string Token { get; set; }
            public string Message { get; set; }
            public DateTime? ExpireTime { get; set; }
        }
        [HttpPost]
        public async Task<AuthenticationResult> Login([FromBody] api_login User)
        {
            var user = await _userManager.FindByNameAsync(User.UserName);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User: " + User.UserName + " does not exist in the system. Please contact to admin.");
                return new AuthenticationResult { HasError = true, Message = "Either the user name or password is incorrect." };
            }
            if (!await _userManager.CheckPasswordAsync(user, User.Password))
            {
                return new AuthenticationResult { HasError = true, Message = "Either the user name or password is incorrect." };
            }


            //if (User.UserName != "demo" || User.Password != "demo")
            //    return new AuthenticationResult { HasError = true, Message = "Either the user name or password is incorrect." };


            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name, User.UserName)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config.GetValue<string>("JWTSecret"));
            //Create token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims, "JWT"),
                //Expires = DateTime.UtcNow.AddMinutes(_config.GetValue<int>("JWTExpiry")),
                Expires = DateTime.Now.AddMinutes(_config.GetValue<int>("JWTExpiry")),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);
            return new AuthenticationResult { Token = jwt, ExpireTime = tokenDescriptor.Expires };
        }
    }
}
