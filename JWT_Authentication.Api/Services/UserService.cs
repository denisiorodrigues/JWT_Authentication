using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JWT_Authentication.Api;

public class UserService : IUserServer
{
    private List<User> _users = new List<User>
    {
        new User {Name = "Admin", Password = "Password" }
    };

    private readonly IConfiguration _configuration;

    public UserService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string Login(User user)
    {
        var userLogin = _users.SingleOrDefault(x => x.Name == user.Name && x.Password == user.Password);

        if(userLogin == null) return string.Empty;

        var tokenHandle = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:key"]);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user.Name)
            }),
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandle.CreateToken(tokenDescriptor);
        var userToken = tokenHandle.WriteToken(token);
        return userToken;
    }
}
