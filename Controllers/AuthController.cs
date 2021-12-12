using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace JwtTokenWithCertificate.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    [HttpGet()]
    [Route("token")]
    public IActionResult Get()
    {
        //perform basic authentication
        var basicAuthToken = Request.Headers[HeaderNames.Authorization].ToString();
        if (!basicAuthToken.StartsWith("Basic")) return BadRequest("Basic authentication failed.");
        var decodedAuthToken = Encoding.UTF8.GetString(Convert.FromBase64String(basicAuthToken[6..].Trim()));
        var userNamePassword = decodedAuthToken.Split(":", 2);
        if (userNamePassword[0] == "admin" && userNamePassword[1] == "pass")
        {
            return Ok(GenerateToken(userNamePassword[0]));
        }
        return BadRequest("Basic authentication failed.");
        
    }

    public string GenerateToken(string user)
    {
        var cert = new X509Certificate2(@"C:\MyCodes\Certificates\nadeem_one.pfx", "1234");
        var securityKey = new X509SecurityKey(cert);
        var secToken = new JwtSecurityToken("www.nadeem.one", "www.nadeem.one",
            new[] {new Claim(ClaimTypes.Name, user)},
            expires:DateTime.Now.AddMinutes(20),
            signingCredentials: new SigningCredentials(securityKey,SecurityAlgorithms.RsaSha256Signature)
        );
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(secToken);
        
    }

    [HttpGet()]
    [Route("order")]
    [Authorize]
    public IActionResult GetOrder()
    {
        return Ok();
    }
}