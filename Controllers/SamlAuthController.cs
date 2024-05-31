using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Saml2AuthDemo.Model;
using Saml2AuthDemoOkta;

namespace Saml2AuthDemo.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class SamlAuthController : ControllerBase
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public SamlAuthController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        [HttpGet("Login")]
        public IActionResult Login(string? returnUrl = null)
        {
            // 轉址的參數設定
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            // 將 SAMLRequest 綁定到 RedirectBinding，並將其轉換為 ActionResult
            var result = binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();

            return result;
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService([FromForm] OktaResponse? oktaResponse)
        {
            // 可以透過 Post 的方式取得 SAMLResponse，例如 oktaResponse
            // 也可透過 Request.Form["SAMLResponse"] 取得
            // 或者直接交由套件處理
            // var samlReponse = Request.Form["SAMLResponse"].ToString();

            try
            {
                var httpRequest = Request.ToGenericHttpRequest(validate: true);

                // Unbind 方法會根據 config 中的設定，驗證 SAMLResponse 是否正確
                // 當然也可以自行驗證，例如驗證 Issuer、Audience、時間戳等
                // 強烈建議要驗證，以避免被惡意攻擊
                var saml2AuthnResponse = new Saml2AuthnResponse(config);
                httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);

                // ClaimsTransform.Transform 是自訂的 Claims 轉換方法，可以將取得的 Claims 轉換為自己需要的格式
                // 詳細請參考 ClaimsTransform.cs
                await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

                try
                {
                    // 如果直接由 IdP 進入，可能會應為缺少 ReturnUrl 而導致錯誤，這邊預設導向首頁
                    var returnUrl = httpRequest.Binding.GetRelayStateQuery()[relayStateReturnUrl];
                    return Redirect(string.IsNullOrWhiteSpace(returnUrl) ? Url.Content("~/") : returnUrl);
                }
                catch
                {
                    return Redirect(Url.Content("~/"));
                }
            }
            catch (Exception ex)
            {
                // TODO: Log exception
                return Unauthorized();
            }
        }


        // https://www.volcengine.com/theme/7054220-R-7-1 
        /// <summary>
        /// 登出並發送 SAML Logout Request 到 IdP 
        /// </summary>
        [HttpGet("Logout")]
        public async Task<IActionResult> Logout()
        {
            // 如果使用者未登入，直接導向首頁(或登入頁)
            if (User.Identity == null || !User.Identity.IsAuthenticated)
                return Redirect(Url.Content("~/"));

            var binding = new Saml2RedirectBinding();

            // 產生 Logout Request，並刪除應用程式登入的 Session
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);

            // 將 SAMLRequest 綁定到 RedirectBinding，並將其轉換為 ActionResult
            var result = binding.Bind(saml2LogoutRequest).ToActionResult();

            return result;
        }

        // 如果要共用同一個 Logout 方法，可以參考底下這篇的寫法
        // https://stackoverflow.com/questions/68001594/saml-2-0-logout-sp-initiated-using-itfoxtec-identity-saml2
        /// <summary>
        /// 收到 IdP 的 Logout Response 後，驗證是否有成功登出
        /// </summary>
        [HttpPost("Logout")]
        public IActionResult LogoutCallback([FromForm] OktaResponse oktaResponse)
        {
            // 可以透過 Post 的方式取得 SAMLResponse，例如 oktaResponse
            // 也可透過 Request.Form["SAMLResponse"] 取得
            // 或者直接交由套件處理
            var samlReponse = Request.Form["SAMLResponse"].ToString();

            var httpRequest = Request.ToGenericHttpRequest(validate: true);

            // Unbind 方法會根據 config 中的設定，驗證 SAMLResponse 是否正確
            // 當然也可以自行驗證，例如驗證 Issuer、Audience、時間戳等
            // 不過這邊其實已經登出了，在一次的驗證只是要確認 Okta 端是否有成功登出而已
            var saml2LogoutResponse = new Saml2LogoutResponse(config);
            httpRequest.Binding.Unbind(httpRequest, saml2LogoutResponse);

            if (saml2LogoutResponse.Status != Saml2StatusCodes.Success)
                throw new Exception("Logout failed : " + saml2LogoutResponse.Status);

            return Redirect(Url.Content("~/"));
        }
    }
}
