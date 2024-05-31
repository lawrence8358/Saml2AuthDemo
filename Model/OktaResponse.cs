namespace Saml2AuthDemo.Model
{ 
    public class OktaResponse
    {
        public string SAMLResponse { get; set; } = string.Empty;

        public string? RelayState { get; set; }
    }
}
