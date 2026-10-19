import { Body, Controller, HttpCode, Module, Post } from '@nestjs/common';
import {
  ApiBadRequestResponse, ApiInternalServerErrorResponse, ApiOkResponse,
  ApiOperation, ApiPayloadTooLargeResponse, ApiTags,
} from '@nestjs/swagger';
import { CryptoService, loadRsaKeys, RSA_KEYS } from './crypto.service';
import { DecryptRequestDto, DecryptResponseDto, EncryptRequestDto, EncryptResponseDto, ErrorResponseDto } from './dto';

@ApiTags('Encryption')
@ApiBadRequestResponse({ description: 'Invalid request or encrypted data', type: ErrorResponseDto })
@ApiPayloadTooLargeResponse({ description: 'Request body exceeds 64 KiB', type: ErrorResponseDto })
@ApiInternalServerErrorResponse({ description: 'Unexpected server error', type: ErrorResponseDto })
@Controller()
export class CryptoController {
  constructor(private readonly crypto: CryptoService) {}

  @Post('get-encrypt-data')
  @HttpCode(200)
  @ApiOperation({ summary: 'Encrypt payload with AES; wrap AES key with RSA private key' })
  @ApiOkResponse({ type: EncryptResponseDto })
  encrypt(@Body() body: EncryptRequestDto): EncryptResponseDto {
    return { successful: true, error_code: '', data: this.crypto.encrypt(body.payload) };
  }

  @Post('get-decrypt-data')
  @HttpCode(200)
  @ApiOperation({ summary: 'Recover AES key with RSA public key; decrypt payload' })
  @ApiOkResponse({ type: DecryptResponseDto })
  decrypt(@Body() body: DecryptRequestDto): DecryptResponseDto {
    return { successful: true, error_code: '', data: this.crypto.decrypt(body.data1, body.data2) };
  }
}

@Module({
  controllers: [CryptoController],
  providers: [CryptoService, { provide: RSA_KEYS, useFactory: loadRsaKeys }],
})
export class AppModule {}
