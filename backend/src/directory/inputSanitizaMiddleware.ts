import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class InputSanitizerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Sanitize query parameters
    if (req.query) {
      Object.keys(req.query).forEach(key => {
        if (typeof req.query[key] === 'string') {
          // Remove potentially dangerous characters
          req.query[key] = (req.query[key] as string)
            .replace(/[<>\"'%;()&+]/g, '')
            .trim()
            .substring(0, 255); // Limit length
        }
      });
    }

    // Sanitize body parameters
    if (req.body && typeof req.body === 'object') {
      this.sanitizeObject(req.body);
    }

    next();
  }

  private sanitizeObject(obj: any) {
    Object.keys(obj).forEach(key => {
      if (typeof obj[key] === 'string') {
        obj[key] = obj[key]
          .replace(/[<>\"'%;()&+]/g, '')
          .trim()
          .substring(0, 1000);
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        this.sanitizeObject(obj[key]);
      }
    });
  }

}
