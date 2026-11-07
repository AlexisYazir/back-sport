import { BadGatewayException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosHeaders, AxiosInstance, AxiosResponse } from 'axios';
import { MlInferenceService } from './ml-inference.service';

function httpResponse(data: unknown): AxiosResponse<unknown> {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: new AxiosHeaders() },
  };
}

describe('MlInferenceService', () => {
  let client: AxiosInstance;
  let service: MlInferenceService;

  beforeEach(() => {
    client = axios.create();
    jest.spyOn(axios, 'create').mockReturnValue(client);
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    service = new MlInferenceService(
      new ConfigService({
        ML_INFERENCE_URL: 'http://ml.example.test',
        ML_INFERENCE_TIMEOUT_MS: '7500',
      }),
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('conserva la configuración y devuelve la respuesta del health check', async () => {
    const create = jest.spyOn(axios, 'create');
    const result = { status: 'ok', model_loaded: true };
    const get = jest
      .spyOn(client, 'get')
      .mockResolvedValue(httpResponse(result));

    await expect(service.health()).resolves.toEqual(result);
    expect(get).toHaveBeenCalledWith('/health');
    expect(create).toHaveBeenCalledWith({
      baseURL: 'http://ml.example.test',
      timeout: 7500,
    });
  });

  it('envía el ID y el límite y conserva el resultado de recomendaciones', async () => {
    const result = {
      product_id: 7,
      recommendations: [{ id_producto: 9, score: 0.98765 }],
      model_version: 'v1',
    };
    const post = jest
      .spyOn(client, 'post')
      .mockResolvedValue(httpResponse(result));

    await expect(service.recommendById(7, 12)).resolves.toEqual(result);
    expect(post).toHaveBeenCalledWith('/v1/products/recommend-by-id', {
      product_id: 7,
      limit: 12,
    });
  });

  const failureCases: Array<{
    name: string;
    failure: unknown;
    expectedDetail: string;
  }> = [
    {
      name: 'detalle de FastAPI',
      failure: {
        response: { data: { detail: 'modelo no disponible' } },
        message: 'HTTP 500',
      },
      expectedDetail: 'modelo no disponible',
    },
    {
      name: 'mensaje de Error',
      failure: new Error('tiempo de espera agotado'),
      expectedDetail: 'tiempo de espera agotado',
    },
    {
      name: 'respuesta de error sin objeto JSON',
      failure: { response: { data: 'no JSON' }, message: 'HTTP 502' },
      expectedDetail: 'HTTP 502',
    },
    {
      name: 'detalle vacío',
      failure: { response: { data: { detail: '' } }, message: 'HTTP 503' },
      expectedDetail: 'HTTP 503',
    },
    {
      name: 'error de texto',
      failure: 'falló la conexión',
      expectedDetail: 'falló la conexión',
    },
    {
      name: 'error nulo',
      failure: null,
      expectedDetail: 'null',
    },
    {
      name: 'error indefinido',
      failure: undefined,
      expectedDetail: 'undefined',
    },
  ];

  it.each(failureCases)(
    'registra $name y devuelve el mensaje público de indisponibilidad',
    async ({ failure, expectedDetail }) => {
      jest.spyOn(client, 'post').mockRejectedValueOnce(failure);
      const log = jest.spyOn(Logger.prototype, 'error');

      await expect(service.recommendById(7, 10)).rejects.toThrow(
        new BadGatewayException('Servicio de inteligencia no disponible'),
      );
      expect(log).toHaveBeenCalledWith(
        `❌ Error en servicio ML http://ml.example.test/v1/products/recommend-by-id: ${expectedDetail}`,
      );
    },
  );

  it('conserva el mensaje específico cuando la conexión es rechazada', async () => {
    jest.spyOn(client, 'get').mockRejectedValueOnce({
      code: 'ECONNREFUSED',
      message: 'connect ECONNREFUSED',
    });

    await expect(service.health()).rejects.toThrow(
      new BadGatewayException(
        'Servicio ML no disponible en http://ml.example.test',
      ),
    );
  });
});
