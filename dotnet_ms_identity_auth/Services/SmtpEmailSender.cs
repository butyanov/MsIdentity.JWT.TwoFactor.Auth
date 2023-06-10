using MailKit.Security;
using MimeKit;
using SmtpClient = MailKit.Net.Smtp.SmtpClient;

namespace dotnet_ms_identity_auth.Services;

public class SmtpSenderService
{
    private readonly IConfiguration _configuration;

    public SmtpSenderService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task SendAsync(string email, string message, string? subject = "Verification Code")
    {
        var userName = "realmail@mail.ru";
        var password = _configuration["Password"];
        var host = _configuration["Host"];
        var port = int.Parse(_configuration["Port"]!);

        using var emailMessage = new MimeMessage();
        emailMessage.From.Add(new MailboxAddress(_configuration["Sender"], userName));
        emailMessage.To.Add(new MailboxAddress("", email));
        emailMessage.Subject = subject;
        
        var bodyBuilder = new BodyBuilder
        {
            HtmlBody = $@"
        <html>
            <head>
                <meta charset=""utf-8"">
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        font-size: 16px;
                        line-height: 1.6;
                        color: #333;
                        background-color: #f7f7f7;
                    }}
                    h1,h3 {{
                        font-size: 28px;
                        font-weight: bold;
                        margin-top: 0;
                    }}
                </style>
            </head>
            <body>
                <h1>{subject}</h1>
                <h3>{message}</p>
            </body>
        </html>"
        };

        emailMessage.Body = bodyBuilder.ToMessageBody();

        using var client = new SmtpClient();
        {
            
                await client.ConnectAsync(host, port, SecureSocketOptions.SslOnConnect);
                await client.AuthenticateAsync(userName, password);
                await client.SendAsync(emailMessage);
                await client.DisconnectAsync(true);
            
        }
    }
}