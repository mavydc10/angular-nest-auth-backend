import { JwtService } from '@nestjs/jwt';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtPayLoad } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private authService: AuthService
  ){}

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {

    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);

    if (!token){
      throw new UnauthorizedException('There is not token');
    }

    try{
      const payload = await this.jwtService.verifyAsync<JwtPayLoad>(
        token,
        {
          secret: process.env.JWT_SEED
        }
      );

      const user = await this.authService.findUserById(payload.id);
      if (!user) throw new UnauthorizedException('User does not exist')
      if (!user.isActive) throw new UnauthorizedException('User does not active')
  
      request['user'] = user;
  
    }
    catch(error){
      throw new UnauthorizedException();
    }

    // 💡 We're assigning the payload to the request object here
    // so that we can access it in our route handlers
    

    return Promise.resolve(true);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
