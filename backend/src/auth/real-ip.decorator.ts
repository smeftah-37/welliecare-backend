import { Injectable } from "@nestjs/common";
import { RedisService } from "src/redis/redis.service";

@Injectable()
export class RateLimiterService {
  constructor(private readonly redisService: RedisService) {}

  async checkRateLimit(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<boolean> {
    const current = await this.redisService.incr(key);
    
    if (current === 1) {
      await this.redisService.expire(key, windowSeconds);
    }
    
    return current > limit;
  }

  async getRemainingAttempts(
    key: string,
    limit: number
  ): Promise<number> {
    const current = await this.redisService.get(key);
    const currentCount = current ? parseInt(current) : 0;
    return Math.max(0, limit - currentCount);
  }
}