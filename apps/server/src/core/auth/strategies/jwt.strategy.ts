import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { EnvironmentService } from '../../../integrations/environment/environment.service';
import { JwtPayload, JwtType } from '../dto/jwt-payload';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { FastifyRequest } from 'fastify';
import { AppRequest } from 'src/common/helpers/types/request';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private userRepo: UserRepo,
    private workspaceRepo: WorkspaceRepo,
    private readonly environmentService: EnvironmentService,
  ) {
    super({
      jwtFromRequest: (req: FastifyRequest) => {
        return req.cookies['token'];
      },
      ignoreExpiration: false,
      secretOrKey: environmentService.getAppSecret(),
      passReqToCallback: true,
    });
  }

  async validate(req: AppRequest, payload: JwtPayload) {
    if (!payload.workspaceId || payload.type !== JwtType.ACCESS) {
      throw new UnauthorizedException();
    }

    // CLOUD ENV
    if (this.environmentService.isCloud()) {
      if (req.raw.workspaceId && req.raw.workspaceId !== payload.workspaceId) {
        throw new BadRequestException('Workspace does not match');
      }
    }

    const workspace = await this.workspaceRepo.findById(payload.workspaceId);

    if (!workspace) {
      throw new UnauthorizedException();
    }
    const user = await this.userRepo.findById(payload.sub, payload.workspaceId);

    if (!user) {
      throw new UnauthorizedException();
    }

    // If the workspace being accessed does not match the user that was
    // authenticated, then the user is not authorized
    if (req.raw.workspaceId !== payload.workspaceId) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
