using Cosmos.Chat.GPT.Options;
using Cosmos.Chat.GPT.Services;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;


using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web.UI;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;


var builder = WebApplication.CreateBuilder(args);

// builder.Services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
//     .AddAzureAD(options => builder.Configuration.Bind("AzureAd", options));
  

builder.Services.AddServerSideBlazor();

// Add Microsoft Identity

// builder.Services.AddScoped<MicrosoftIdentityService>();


// Add Microsoft Identity UI

// builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.OpenIdConnectScheme, options =>
// {
//     options.Events.OnTokenValidated = async context =>
//     {
//         // Add logic here to add additional claims or modify existing ones
//     };
// });





builder.RegisterConfiguration();

builder.Services.RegisterServices();




var app = builder.Build();


if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Use Authentication and Authorization



  // More code
  app.UseEndpoints(endpoints =>
  {
   endpoints.MapRazorPages();  // If Razor pages
   endpoints.MapControllers(); // Needs to be added
  });
 

app.UseAuthentication();
app.UseAuthorization();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

await app.RunAsync();
static class ProgramExtensions
{
    public static void RegisterConfiguration(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<CosmosDb>()
            .Bind(builder.Configuration.GetSection(nameof(CosmosDb)));

        builder.Services.AddOptions<OpenAi>()
            .Bind(builder.Configuration.GetSection(nameof(OpenAi)));

        builder.Services.AddRazorPages().AddMvcOptions(options =>
            {
            var policy = new AuthorizationPolicyBuilder()
                            .RequireAuthenticatedUser()
                            .Build();
                        options.Filters.Add(new AuthorizeFilter(policy));
            });
            
        builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));

        builder.Services.Configure<CookiePolicyOptions>(options =>
        {
            options.Secure = CookieSecurePolicy.Always;
            options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
            options.MinimumSameSitePolicy = SameSiteMode.Lax;
        });



    }

    public static void RegisterServices(this IServiceCollection services)
    {
        services.AddSingleton<CosmosDbService, CosmosDbService>((provider) =>
        {
            var cosmosDbOptions = provider.GetRequiredService<IOptions<CosmosDb>>();
            if (cosmosDbOptions is null)
            {
                throw new ArgumentException($"{nameof(IOptions<CosmosDb>)} was not resolved through dependency injection.");
            }
            else
            {
                return new CosmosDbService(
                    endpoint: cosmosDbOptions.Value?.Endpoint ?? String.Empty,
                    key: cosmosDbOptions.Value?.Key ?? String.Empty,
                    databaseName: cosmosDbOptions.Value?.Database ?? String.Empty,
                    containerName: cosmosDbOptions.Value?.Container ?? String.Empty
                );
            }
        });
        services.AddSingleton<OpenAiService, OpenAiService>((provider) =>
        {
            var openAiOptions = provider.GetRequiredService<IOptions<OpenAi>>();
            if (openAiOptions is null)
            {
                throw new ArgumentException($"{nameof(IOptions<OpenAi>)} was not resolved through dependency injection.");
            }
            else
            {
                return new OpenAiService(
                    endpoint: openAiOptions.Value?.Endpoint ?? String.Empty,
                    key: openAiOptions.Value?.Key ?? String.Empty,
                    deploymentName: openAiOptions.Value?.Deployment ?? String.Empty,
                    maxConversationTokens: openAiOptions.Value?.MaxConversationTokens ?? String.Empty
                );
            }
        });
        services.AddSingleton<ChatService>();
    }
}
