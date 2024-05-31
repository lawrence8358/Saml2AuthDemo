using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Saml2AuthDemo.Pages
{
    [Authorize]
    public class TestModel : PageModel
    {
        private readonly ILogger<TestModel> _logger;

        public TestModel(ILogger<TestModel> logger)
        {
            _logger = logger;
        }
         
        public void OnGet()
        {
        }
    }

}
