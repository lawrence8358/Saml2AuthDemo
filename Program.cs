using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Util;

namespace Saml2AuthDemo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorPages();

            AddAuthService(builder);

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                // app.UseHsts();
            }

            // app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseSaml2();

            app.UseAuthentication();

            app.UseAuthorization();

            // app.UseSession();

            app.MapControllers();

            app.MapRazorPages();

            app.Run();
        }

        private static void AddAuthService(WebApplicationBuilder builder)
        {
            IConfiguration configuration = builder.Configuration;
            IWebHostEnvironment environment = builder.Environment;

            // https://developer.okta.com/blog/2020/10/23/how-to-authenticate-with-saml-in-aspnet-core-and-csharp
            builder.Services
                .Configure<Saml2Configuration>(configuration.GetSection("Saml2"))
                .Configure<Saml2Configuration>(saml2Configuration =>
                {
                    // 配置 SAML2 服務提供者(SP)
                    var spCert = CertificateUtil.Load(configuration["Saml2:SigningCertificateFile"], configuration["Saml2:SigningCertificatePassword"]);
                    saml2Configuration.SigningCertificate = spCert;
                    saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);


                    // 配置 SAML2 身份提供者(IdP)
                    var entityDescriptor = new EntityDescriptor();
                    entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(configuration["Saml2:IdPMetadata"])); // 取得 IdP 的 Metadata

                    if (entityDescriptor.IdPSsoDescriptor != null)
                    {
                        var idpSsoDescriptor = entityDescriptor.IdPSsoDescriptor;
                        var singleSignOnService = idpSsoDescriptor.SingleSignOnServices.First().Location; // Idp 的登入網址
                        var singleLogoutService = idpSsoDescriptor.SingleLogoutServices.FirstOrDefault()?.Location; // Idp 的登出網址
                        var signingCertificates = idpSsoDescriptor.SigningCertificates;  // Idp 的憑證

                        saml2Configuration.SingleSignOnDestination = singleSignOnService;
                        saml2Configuration.SingleLogoutDestination = singleLogoutService;
                        saml2Configuration.SignatureValidationCertificates.AddRange(signingCertificates);
                    }
                    else
                    {
                        throw new Exception("IdPSsoDescriptor not loaded from metadata.");
                    }
                })
                .AddSaml2(loginPath: "/SamlAuth/Login");
        }
    }
}
