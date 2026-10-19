import 'reflect-metadata';
import {
  ArgumentsHost, Catch, ExceptionFilter, HttpException, Logger, ValidationPipe,
} from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Response } from 'express';
import { AppModule } from './app.module';

@Catch()
export class ApiExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ApiExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    // Express body-parser errors do not extend Nest's HttpException.
    const status = exception instanceof HttpException ? exception.getStatus()
      : exception instanceof Error && 'status' in exception && exception.status === 413 ? 413 : 500;
    const errorCodes: Record<number, string> = {
      400: 'VALIDATION_ERROR', 404: 'NOT_FOUND', 413: 'PAYLOAD_TOO_LARGE',
    };
    const errorCode = exception instanceof HttpException && exception.message === 'INVALID_ENCRYPTED_DATA'
      ? 'INVALID_ENCRYPTED_DATA' : errorCodes[status] ?? 'INTERNAL_ERROR';
    if (status >= 500) this.logger.error('Unhandled request error', exception instanceof Error ? exception.stack : undefined);
    host.switchToHttp().getResponse<Response>().status(status).json({
      successful: false, error_code: errorCode, data: null,
    });
  }
}

export async function createApp(logger: false | undefined = undefined): Promise<NestExpressApplication> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { logger, abortOnError: false });
  app.disable('x-powered-by');
  app.useBodyParser('json', { limit: '64kb' });
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true, forbidNonWhitelisted: true, transform: true,
    validationError: { target: false, value: false },
  }));
  app.useGlobalFilters(new ApiExceptionFilter());
  const document = new DocumentBuilder()
    .setTitle('Primo Encryption API')
    .setDescription('AES-256-GCM payload encryption with RSA private-key wrapping/public-key recovery. Anyone with the public key can decrypt; this flow does not provide confidentiality against public-key holders.')
    .setVersion('1.0.0')
    .build();
  SwaggerModule.setup('api-docs', app, SwaggerModule.createDocument(app, document));
  app.enableShutdownHooks();
  return app;
}
