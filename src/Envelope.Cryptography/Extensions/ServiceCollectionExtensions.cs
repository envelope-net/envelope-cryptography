using Envelope.Cryptography.Signing;
using Envelope.Cryptography.Signing.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Envelope.Cryptography.Extensions;

public static class ServiceCollectionExtensions
{
	public static IServiceCollection AddSigner(this IServiceCollection services)
	{
		services.TryAddSingleton<ISigner, Signer>();
		return services;
	}
}
