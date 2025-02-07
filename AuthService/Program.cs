using AuthService.Data;
using AuthService.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using AuthService.Services.Interfaces;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// Конфигурация сервисов
builder.Services.AddDbContext<AppDbContext>(options => 
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// builder.Services.AddStackExchangeRedisCache(options => 
//     options.Configuration = builder.Configuration.GetConnectionString("Redis"));

builder.Services.AddSingleton<IConnectionMultiplexer>(_ => 
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")));

builder.Services.AddScoped<IAuthService, AuthService.Services.Implementations.AuthService>();
builder.Services.AddControllers();

// Настройка JWT через метод расширения
builder.Services.ConfigureJwt(builder.Configuration);

// Swagger с поддержкой JWT
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth Service", Version = "v1" });
    
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Автоматическое применение миграций
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    dbContext.Database.Migrate();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();