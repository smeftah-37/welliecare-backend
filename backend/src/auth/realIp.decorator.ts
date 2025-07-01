import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export const RealIp = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest<Request>();
    
    // Get the direct connection IP
    const directIP = request.connection?.remoteAddress || request.socket?.remoteAddress;
    
    // Your trusted proxy IPs (CORRIGÉ: 10.0.53.20 au lieu de 10.0.53.10)
    const trustedProxies = ['10.0.53.20', '10.0.52.20']; // Vos serveurs Nginx
    

    
    // Check if request comes from trusted proxy
    const cleanDirectIP = directIP?.replace('::ffff:', '') || ''; // Nettoyer l'IPv6 mapping
    const isTrustedProxy = trustedProxies.includes(cleanDirectIP);
    
 
    
    if (isTrustedProxy) {
      // Priorité 1: X-Original-IP (votre header personnalisé)
      const originalIp = request.headers['x-original-ip'];
      if (originalIp && typeof originalIp === 'string') {
        return originalIp;
      }
      
      // Priorité 2: X-Real-IP
      const realIp = request.headers['x-real-ip'];
      if (realIp && typeof realIp === 'string') {
        return realIp;
      }
      
      // Priorité 3: X-Forwarded-For (premier IP de la liste)
      const forwardedFor = request.headers['x-forwarded-for'];
      if (forwardedFor && typeof forwardedFor === 'string') {
        const firstIp = forwardedFor.split(',')[0].trim();
        return firstIp;
      }
      
      // Priorité 4: Cloudflare (si utilisé)
      const cfConnectingIp = request.headers['cf-connecting-ip'];
      if (cfConnectingIp && typeof cfConnectingIp === 'string') {
        return cfConnectingIp;
      }
    }
    
    // Fallback: IP directe (nettoyée)
    const fallbackIp = cleanDirectIP || 'unknown';
    return fallbackIp;
  }
);