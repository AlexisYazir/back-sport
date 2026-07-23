import { Controller, Get, Param, ParseIntPipe, Query } from '@nestjs/common';
import { DataMiningReportsService } from './data-mining-reports.service';

@Controller('products/recommendations')
export class ProductRecommendationsController {
  constructor(private readonly dataMiningReportsService: DataMiningReportsService) {}

  @Get(':productId')
  getRecommendations(
    @Param('productId', ParseIntPipe) productId: number,
    @Query('limit') limit?: string,
  ) {
    const parsedLimit = Math.min(Math.max(Number(limit) || 4, 1), 10);
    return this.dataMiningReportsService.getProductRecommendations(productId, parsedLimit);
  }
}
