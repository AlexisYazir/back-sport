import {
  Body,
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import {
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';
import { AuthGuard } from '@nestjs/passport';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AccountDeletionService } from './account-deletion.service';
import {
  AccountDeletionMutationGuard,
  DeletionNoStoreInterceptor,
} from './account-deletion.guards';
import type { DeletionPrincipal } from './deletion.types';
import { RolesGuard } from '../../services/auth/roles.guard';
import { Roles } from '../../services/auth/roles.decorator';
import { ActiveAdminGuard } from '../../services/auth/active-admin.guard';

class VerifyDeletionDto {
  @Matches(/^\d{6}$/) code: string;
}
class ConfirmDeletionDto {
  @IsString() @Matches(/^[A-Za-z\d_-]{43}$/) confirmationToken: string;
  @IsBoolean() confirmed: boolean;
}
class ReceiptDto {
  @IsString() @Matches(/^[A-Za-z\d_-]{43}$/) receiptToken: string;
}
class ProcessDeletionDto {
  @IsOptional() @IsString() @MinLength(10) @MaxLength(1000) basis?: string;
  @IsOptional() @IsInt() @Min(1) @Max(36500) days?: number;
}
type DeletionRequest = Request & { user: DeletionPrincipal };

@Controller('users/account-deletion')
@UseInterceptors(DeletionNoStoreInterceptor)
export class AccountDeletionController {
  constructor(private readonly service: AccountDeletionService) {}

  @Post('requests')
  @UseGuards(AuthGuard('jwt'), AccountDeletionMutationGuard)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  request(@Req() req: DeletionRequest) {
    return this.service.request(req.user);
  }

  @Post('requests/:id/verify')
  @UseGuards(AuthGuard('jwt'), AccountDeletionMutationGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  verify(
    @Req() req: DeletionRequest,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: VerifyDeletionDto,
  ) {
    return this.service.verify(req.user, id, body.code);
  }

  @Post('requests/:id/confirm')
  @UseGuards(AuthGuard('jwt'), AccountDeletionMutationGuard)
  confirm(
    @Req() req: DeletionRequest,
    @Res({ passthrough: true }) res: Response,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: ConfirmDeletionDto,
  ) {
    return this.service
      .confirm(req.user, id, body.confirmationToken, body.confirmed)
      .then((result) => {
        for (const name of ['sc_access_token', 'sc_refresh_token']) {
          res.clearCookie(name, { httpOnly: true, path: '/', sameSite: 'lax' });
          res.clearCookie(name, {
            httpOnly: true,
            path: '/',
            secure: true,
            sameSite: 'none',
          });
        }
        return result;
      });
  }

  @Post('requests/:id/result')
  @UseGuards(AccountDeletionMutationGuard)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  result(
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: ReceiptDto,
  ) {
    return this.service.result(id, body.receiptToken);
  }

  @Get('admin/requests')
  @UseGuards(AuthGuard('jwt'), RolesGuard, ActiveAdminGuard)
  @Roles(3)
  pending() {
    return this.service.listPending();
  }

  @Post('admin/requests/:id/process')
  @UseGuards(
    AuthGuard('jwt'),
    RolesGuard,
    ActiveAdminGuard,
    AccountDeletionMutationGuard,
  )
  @Roles(3)
  process(
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: ProcessDeletionDto,
  ) {
    return this.service.process(
      id,
      body.basis && body.days
        ? { basis: body.basis, days: body.days }
        : undefined,
    );
  }
}
