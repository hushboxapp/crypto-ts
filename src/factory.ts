import { ProviderNotFoundError } from './errors';

export interface NamedProvider {
  name: string;
}

export class Factory<T extends NamedProvider> {
  constructor(private readonly type: string) {}

  private providers = new Map<string, T>();

  addProvider(provider: T): void {
    this.providers.set(provider.name, provider);
  }

  getProvider(name: string): T {
    const provider = this.providers.get(name);

    if (!provider) {
      throw new ProviderNotFoundError(this.type, name);
    }

    return provider;
  }
}
