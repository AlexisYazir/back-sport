import { IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';

export class GoogleLoginDto {
  @IsString()
  @IsNotEmpty()
  idToken: string;

  @IsOptional()
  @IsString()
  @MaxLength(150)
  deviceName?: string;
}
