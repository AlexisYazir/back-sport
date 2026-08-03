import { BadGatewayException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';

export interface DemandPredictionRequest {
  id_variante: number;
  // Features base (historial de ventas)
  cantidad_hace_3_meses: number;
  cantidad_hace_2_meses: number;
  cantidad_mes_anterior: number;
  mes_objetivo?: string;
  // Features derivadas que el modelo espera (calcular en el servicio)
  mes_num?: number;
  mes_sin?: number;
  mes_cos?: number;
  q1?: number;
  q2?: number;
  q3?: number;
  q4?: number;
  lag_mean?: number;
  lag_weighted?: number;
  lag_trend?: number;
  lag_last_delta?: number;
  lag_volatility?: number;
  lag_min?: number;
  lag_max?: number;
  zero_lags?: number;
}

export interface DemandPredictionResponse {
  id_variante: number;
  predicted_units: number;
  model_version?: string;
  algorithm?: string;
}

export interface ProductRecommendationFeatures {
  id_producto: number;
  nombre_producto: string;
  descripcion: string;
  categoria: string;
  categoria_padre: string;
  marca: string;
  deportes: string[];
  atributos: string | Record<string, unknown>;
  precio_promedio: number;
}

export interface ProductRecommendationResponse {
  product_id: number;
  model_version?: string;
  algorithm?: string;
  recommendations: Array<{
    id_producto: number;
    score: number;
  }>;
}

export interface RecommendByIdRequest {
  product_id: number;
  limit: number;
}

@Injectable()
export class MlInferenceService {
  private readonly logger = new Logger(MlInferenceService.name);
  private readonly client: AxiosInstance;

  constructor(private readonly configService: ConfigService) {
    const baseURL =
      this.configService.get<string>('ML_INFERENCE_URL') ||
      'http://127.0.0.1:8001';
    this.client = axios.create({
      baseURL,
      timeout: Number(this.configService.get('ML_INFERENCE_TIMEOUT_MS') || 8000),
    });
  }

  async health(): Promise<Record<string, unknown>> {
    const response = await this.request<Record<string, unknown>>('get', '/health');
    return response;
  }

  async predictDemand(
    payload: DemandPredictionRequest,
  ): Promise<DemandPredictionResponse> {
    return this.request<DemandPredictionResponse>(
      'post',
      '/v1/demand/predict',
      payload,
    );
  }

  async recommendProducts(
    product: ProductRecommendationFeatures,
    limit: number,
  ): Promise<ProductRecommendationResponse> {
    return this.request<ProductRecommendationResponse>(
      'post',
      '/v1/products/recommend',
      { product, limit },
    );
  }

  /**
   * Nuevo método: Recomendación por ID de producto
   * Optimizado para enviar solo el ID y evitar enviar datos redundantes
   */
  async recommendById(
    productId: number,
    limit: number,
  ): Promise<ProductRecommendationResponse> {
    const payload: RecommendByIdRequest = {
      product_id: productId,
      limit,
    };
    return this.request<ProductRecommendationResponse>(
      'post',
      '/v1/products/recommend-by-id',
      payload,
    );
  }

  private async request<T>(
    method: 'get' | 'post',
    url: string,
    data?: unknown,
  ): Promise<T> {
    try {
      const response =
        method === 'get'
          ? await this.client.get<T>(url)
          : await this.client.post<T>(url, data);
      return response.data;
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || error;
      this.logger.error(`Error en servicio ML ${url}: ${detail}`);
      throw new BadGatewayException('Servicio de inteligencia no disponible');
    }
  }
  
  
}

