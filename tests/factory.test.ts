import { describe, it, expect } from 'vitest';
import { Factory, NamedProvider } from '../src/factory';
import { ProviderNotFoundError } from '../src/errors';

describe('Factory', () => {
  interface TestProvider extends NamedProvider {
    doSomething(): string;
  }

  it('should register and retrieve a provider', () => {
    const factory = new Factory<TestProvider>('Test');
    const provider: TestProvider = {
      name: 'test-p',
      doSomething: () => 'done'
    };

    factory.addProvider(provider);
    const retrieved = factory.getProvider('test-p');
    
    expect(retrieved).toBe(provider);
    expect(retrieved.doSomething()).toBe('done');
  });

  it('should throw ProviderNotFoundError for non-existent provider', () => {
    const factory = new Factory<TestProvider>('Test');
    expect(() => factory.getProvider('missing')).toThrow(ProviderNotFoundError);
  });

  it('should overwrite provider with the same name', () => {
    const factory = new Factory<TestProvider>('Test');
    const p1: TestProvider = { name: 'p', doSomething: () => '1' };
    const p2: TestProvider = { name: 'p', doSomething: () => '2' };

    factory.addProvider(p1);
    expect(factory.getProvider('p').doSomething()).toBe('1');

    factory.addProvider(p2);
    expect(factory.getProvider('p').doSomething()).toBe('2');
  });
});
