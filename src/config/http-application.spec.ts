import type { Server } from 'node:http';
import { Body, Controller, type INestApplication, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { CreateContactMessageDto } from '../modules/company/dto/create-contact-message.dto';
import { configureHttpApplication } from './http-application';

const received: CreateContactMessageDto[] = [];

@Controller('contact-probe')
class ContactProbeController {
  @Post()
  create(@Body() dto: CreateContactMessageDto): { accepted: boolean } {
    received.push(dto);
    return { accepted: true };
  }
}

describe('shared HTTP application configuration', () => {
  let app: INestApplication<Server> | undefined;
  const validContact = {
    nombre: 'Cliente QA HTTP',
    email: 'http-probe@qa.invalid',
    asunto: 'Reporte sintetico QA',
    mensaje: 'Mensaje sintetico para comprobar el contrato HTTP.',
  };

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      controllers: [ContactProbeController],
    }).compile();
    app = module.createNestApplication<INestApplication<Server>>();
    configureHttpApplication(app);
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    expect(address && typeof address === 'object' && address.address).toBe(
      '127.0.0.1',
    );
  });

  beforeEach(() => {
    received.length = 0;
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  it.each([
    { field: 'leido', value: true },
    { field: 'respondido', value: true },
    { field: 'id_usuario_responde', value: 310003 },
  ])(
    'rejects the internal contact field $field before the controller',
    async ({ field, value }) => {
      await request(app!.getHttpServer())
        .post('/contact-probe')
        .send({ ...validContact, [field]: value })
        .expect(400);
      expect(received).toEqual([]);
    },
  );

  it('delivers a valid transformed contact DTO to the controller', async () => {
    await request(app!.getHttpServer())
      .post('/contact-probe')
      .send(validContact)
      .expect(201, { accepted: true });
    expect(received).toHaveLength(1);
    expect(received[0]).toBeInstanceOf(CreateContactMessageDto);
    expect(received[0]).toEqual(validContact);
  });

  it('allows the retry header and credentials in an authorized preflight', async () => {
    const origin = 'http://localhost:4200';
    const response = await request(app!.getHttpServer())
      .options('/contact-probe')
      .set('Origin', origin)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type,x-auth-retry')
      .expect(204);
    expect(response.headers['access-control-allow-origin']).toBe(origin);
    expect(response.headers['access-control-allow-credentials']).toBe('true');
    expect(
      String(response.headers['access-control-allow-headers']).toLowerCase(),
    ).toContain('x-auth-retry');
  });

  it('does not authorize an unknown origin', async () => {
    const response = await request(app!.getHttpServer())
      .options('/contact-probe')
      .set('Origin', 'https://untrusted-qa.invalid')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type,x-auth-retry');
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });
});
