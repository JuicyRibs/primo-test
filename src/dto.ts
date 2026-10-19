import { ApiProperty } from '@nestjs/swagger';
import { IsBase64, IsNotEmpty, IsString, MaxLength } from 'class-validator';

export class EncryptRequestDto {
  @ApiProperty({ example: 'Hello NestJS', minLength: 0, maxLength: 2000 })
  @IsString()
  @MaxLength(2000)
  payload!: string;
}

export class DecryptRequestDto {
  @ApiProperty({ description: 'Base64 RSA-encrypted AES key', format: 'byte', minLength: 1 })
  @IsString()
  @IsNotEmpty()
  @IsBase64()
  data1!: string;

  @ApiProperty({ description: 'Base64 of IV (12 bytes) + GCM tag (16 bytes) + ciphertext', format: 'byte', minLength: 1 })
  @IsString()
  @IsNotEmpty()
  @IsBase64()
  data2!: string;
}

export class EncryptedDataDto {
  @ApiProperty({ description: 'Base64 RSA-encrypted AES key' })
  data1!: string;

  @ApiProperty({ description: 'Base64 of IV + GCM tag + ciphertext' })
  data2!: string;
}

export class DecryptedDataDto {
  @ApiProperty({ example: 'Hello NestJS' })
  payload!: string;
}

export class EncryptResponseDto {
  @ApiProperty({ example: true })
  successful!: boolean;

  @ApiProperty({ example: '' })
  error_code!: string;

  @ApiProperty({ type: EncryptedDataDto, nullable: true })
  data!: EncryptedDataDto | null;
}

export class DecryptResponseDto {
  @ApiProperty({ example: true })
  successful!: boolean;

  @ApiProperty({ example: '' })
  error_code!: string;

  @ApiProperty({ type: DecryptedDataDto, nullable: true })
  data!: DecryptedDataDto | null;
}

export class ErrorResponseDto {
  @ApiProperty({ example: false })
  successful!: boolean;

  @ApiProperty({ example: 'VALIDATION_ERROR', description: 'See README for error codes and HTTP statuses.' })
  error_code!: string;

  @ApiProperty({ type: 'object', properties: {}, nullable: true, example: null })
  data!: null;
}
