using Microsoft.AspNetCore.Mvc;

namespace JWTAuth
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController: ControllerBase
    {
        public static User user = new User();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDataTransferObject request)
        {
            return Ok("");
        }


    }
}
