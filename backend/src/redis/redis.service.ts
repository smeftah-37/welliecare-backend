import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis'; // Correct import

@Injectable()
export class RedisService implements OnModuleDestroy {
  private client: Redis;
  private pipeline: ReturnType<Redis['pipeline']>;

  constructor(private configService: ConfigService) {
    this.client = new Redis({
      host: this.configService.get<string>('REDIS_HOST', 'localhost'),
      port: this.configService.get<number>('REDIS_PORT', 6379),
      password: this.configService.get<string>('REDIS_PASSWORD'),
      db: this.configService.get<number>('REDIS_DB', 0),
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
      // Connection pooling
      enableOfflineQueue: true,
      connectTimeout: 10000,
      // Performance optimizations
      lazyConnect: true,
      keyPrefix: 'auth:',
    });

    this.pipeline = this.client.pipeline();
  }

  async onModuleDestroy() {
    await this.client.quit();
  }

  // Optimized methods with pipelining
  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      await this.client.set(key, value, 'EX', ttl);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);
    return result === 1;
  }

  async expire(key: string, seconds: number): Promise<void> {
    await this.client.expire(key, seconds);
  }

  // Add the missing ttl method
  async ttl(key: string): Promise<number> {
    return this.client.ttl(key);
  }

  async incr(key: string): Promise<number> {
    return this.client.incr(key);
  }

  async sadd(key: string, member: string): Promise<void> {
    await this.client.sadd(key, member);
  }

  async smembers(key: string): Promise<string[]> {
    return this.client.smembers(key);
  }

  async srem(key: string, member: string): Promise<void> {
    await this.client.srem(key, member);
  }

  async scard(key: string): Promise<number> {
    return this.client.scard(key);
  }

  async rpush(key: string, value: string): Promise<void> {
    await this.client.rpush(key, value);
  }

  // Batch operations for performance
  async batchGet(keys: string[]): Promise<(string | null)[]> {
    if (keys.length === 0) return [];
    return this.client.mget(...keys);
  }

  async batchSet(items: { key: string; value: string; ttl?: number }[]): Promise<void> {
    const pipeline = this.client.pipeline();
    
    for (const item of items) {
      if (item.ttl) {
        pipeline.set(item.key, item.value, 'EX', item.ttl);
      } else {
        pipeline.set(item.key, item.value);
      }
    }
    
    await pipeline.exec();
  }
}
