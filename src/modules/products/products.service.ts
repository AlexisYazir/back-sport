import { Injectable } from '@nestjs/common';

import { CreateCategorieDto } from './dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from './dto/categories/update-categorie.dto';
import { CreateInventoryMovementDto } from './dto/inventory/create-inventory_movement.dto';
import { CreateInventoryMovementSkuDto } from './dto/inventory/create-inventory-movement-sku.dto';
import { CreateMarcaDto } from './dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from './dto/marca/update-marca.dto';
import { CreateAttributeDto } from './dto/product/create-attribute.dto';
import { CreateProductDto } from './dto/product/create-product.dto';
import { CreateProductSportsDto } from './dto/product/create-product-sports.dto';
import { CreateProductVariantDto } from './dto/product/create-product_variant.dto';
import { CreateVarAttributeValuesDto } from './dto/product/create-var-att_vls.dto';
import {
  UpdateProductFullDto,
  UpdateProductResult,
} from './dto/product/update-product-full.dto';
import { UpdateProductInvDto } from './dto/product/update-product-inv.dto';
import {
  UpdateProductVariantAttributeDto,
  UpdateProductVarAttResult,
} from './dto/product/update.product-var-attr.dto';
import { Category } from './entities/categorie/categorie.entity';
import { InventoryMovements } from './entities/inventory/inventory_movements.entity';
import { Marca } from './entities/marca/marca.entity';
import { Orders } from './entities/orders/orders.entity';
import { Attribute } from './entities/product/atributtes.entity';
import { Product } from './entities/product/product.entity';
import { ProductVariant } from './entities/product/product_variant.entity';
import { VariantAttributeValue } from './entities/product/variant_attr_vals.entity';
import { Sports } from './entities/sports/sport.entity';
import { CreateReviewDto } from './dto/reviews/create-review.dto';
import { CloudinaryUploadResult } from './services/cloudinary.service';
import { ProductBrandCategoryService } from './services/product-brand-category.service';
import { ProductCatalogService } from './services/product-catalog.service';
import { ProductInventoryService } from './services/product-inventory.service';
import { ProductOrdersService } from './services/product-orders.service';
import { ProductReviewsService } from './services/product-reviews.service';
import { ProductReviewModerationService } from './services/product-review-moderation.service';
import {
  ModerateReviewDto,
  ReviewReportsQueryDto,
} from './dto/reviews/moderation.dto';
import type {
  PublicReview,
  ReviewModerationDetail,
  ReviewReportPage,
} from './types/review-moderation.types';
import { ProductCartService } from './services/product-cart.service';
import { ProductCheckoutService } from './services/product-checkout.service';
import { ProductPromotionsService } from './services/product-promotions.service';
import { AddCartItemDto } from './dto/cart/add-cart-item.dto';
import { UpdateCartItemDto } from './dto/cart/update-cart-item.dto';
import {
  CheckoutCardDto,
  CreateCheckoutOrderDto,
} from './dto/checkout/create-checkout-order.dto';
import { UpdateShipmentDto } from './dto/orders/update-shipment.dto';
import {
  CreateReturnDto,
  UpdateReturnStatusDto,
} from './dto/returns/create-return.dto';
import {
  CreatePromotionDto,
  UpdatePromotionDto,
  UpdateShippingMethodDto,
} from './dto/promotions/promotion.dto';

export interface ExcelImportResult {
  success: number;
  errors: Array<{
    row: number;
    sku: string;
    error: string;
    data: any;
  }>;
  total: number;
}

@Injectable()
export class ProductsService {
  constructor(
    private readonly catalogService: ProductCatalogService,
    private readonly inventoryService: ProductInventoryService,
    private readonly brandCategoryService: ProductBrandCategoryService,
    private readonly ordersService: ProductOrdersService,
    private readonly reviewsService: ProductReviewsService,
    private readonly cartService: ProductCartService,
    private readonly checkoutService: ProductCheckoutService,
    private readonly promotionsService: ProductPromotionsService,
    private readonly reviewModerationService: ProductReviewModerationService,
  ) {}

  createProduct(createProductDto: CreateProductDto): Promise<Product> {
    return this.catalogService.createProduct(createProductDto);
  }

  assignProductSports(dto: CreateProductSportsDto): Promise<{
    id_producto: number;
    deportes_asignados: number;
  }> {
    return this.catalogService.assignProductSports(dto);
  }

  uploadImage(
    file: Express.Multer.File,
    folder?: string,
  ): Promise<CloudinaryUploadResult> {
    return this.catalogService.uploadImage(file, folder);
  }

  createProductVariant(dto: CreateProductVariantDto): Promise<ProductVariant> {
    return this.catalogService.createProductVariant(dto);
  }

  createAttribute(dto: CreateAttributeDto): Promise<Attribute> {
    return this.catalogService.createAttribute(dto);
  }

  createVariantAttributeValue(
    dto: CreateVarAttributeValuesDto,
  ): Promise<VariantAttributeValue> {
    return this.catalogService.createVariantAttributeValue(dto);
  }

  getAllProducts(): Promise<unknown[]> {
    return this.catalogService.getAllProducts();
  }

  getRecientProducts(): Promise<unknown[]> {
    return this.catalogService.getRecientProducts();
  }

  getProductsWithoutVariantsAttributes(): Promise<unknown[]> {
    return this.catalogService.getProductsWithoutVariantsAttributes();
  }

  getVariantsByProduct(id: number): Promise<unknown[]> {
    return this.catalogService.getVariantsByProduct(id);
  }

  getProductDetail(id: number): Promise<unknown[]> {
    return this.catalogService.getProductDetail(id);
  }

  updateProductFull(dto: UpdateProductFullDto): Promise<UpdateProductResult> {
    return this.catalogService.updateProductFull(dto);
  }

  updateProductVariant(
    dto: UpdateProductVariantAttributeDto,
  ): Promise<UpdateProductVarAttResult> {
    return this.catalogService.updateProductVariant(dto);
  }

  getAttributes(): Promise<Attribute[]> {
    return this.catalogService.getAttributes();
  }

  getInventoryProducts(): Promise<unknown[]> {
    return this.inventoryService.getInventoryProducts();
  }

  updateProductInv(dto: UpdateProductInvDto): Promise<number> {
    return this.inventoryService.updateProductInv(dto);
  }

  createInventoryMovementBySku(
    dto: CreateInventoryMovementSkuDto,
  ): Promise<InventoryMovements> {
    return this.inventoryService.createInventoryMovementBySku(dto);
  }

  createInventoryMovement(
    dto: CreateInventoryMovementDto,
  ): Promise<InventoryMovements> {
    return this.inventoryService.createInventoryMovement(dto);
  }

  bulkCreateInventoryMovements(
    movements: CreateInventoryMovementSkuDto[],
  ): Promise<{ success: number; errors: any[] }> {
    return this.inventoryService.bulkCreateInventoryMovements(movements);
  }

  getInventoryMovements(): Promise<InventoryMovements[]> {
    return this.inventoryService.getInventoryMovements();
  }

  getVariantsForInventoryMovement(): Promise<unknown[]> {
    return this.inventoryService.getVariantsForInventoryMovement();
  }

  createMarca(dto: CreateMarcaDto): Promise<Marca> {
    return this.brandCategoryService.createMarca(dto);
  }

  updateMarca(dto: UpdateMarcaDto): Promise<Marca> {
    return this.brandCategoryService.updateMarca(dto);
  }

  getMarcas(): Promise<Marca[]> {
    return this.brandCategoryService.getMarcas();
  }

  createCategory(dto: CreateCategorieDto): Promise<Category> {
    return this.brandCategoryService.createCategory(dto);
  }

  updateCategory(dto: UpdateCategorieDto): Promise<Category> {
    return this.brandCategoryService.updateCategory(dto);
  }

  getCategories(): Promise<Category[]> {
    return this.brandCategoryService.getCategories();
  }

  getCategoriesByParent(parentId: number): Promise<Category[]> {
    return this.brandCategoryService.getCategoriesByParent(parentId);
  }

  getSports(): Promise<Sports[]> {
    return this.brandCategoryService.getSports();
  }

  getCompleteMenu(): Promise<unknown> {
    return this.brandCategoryService.getCompleteMenu();
  }

  getOrderDetail(id: number): Promise<unknown[]> {
    return this.ordersService.getOrderDetail(id);
  }

  getAllOrders(): Promise<unknown[]> {
    return this.ordersService.getAllOrders();
  }

  getOrderss(): Promise<Orders[]> {
    return this.ordersService.getOrderss();
  }

  getEmployeeOrders(): Promise<unknown[]> {
    return this.ordersService.getEmployeeOrders();
  }

  getUserOrders(id_usuario: number): Promise<unknown[]> {
    return this.ordersService.getUserOrders(id_usuario);
  }

  updateOrderStatus(
    id_orden: number,
    estado: string,
    cambiado_por?: number,
  ): Promise<{ message: string; order: Orders }> {
    return this.ordersService.updateOrderStatus(id_orden, estado, cambiado_por);
  }

  getOrderTracking(id_usuario: number, id_orden: number): Promise<unknown> {
    return this.ordersService.getOrderTracking(id_usuario, id_orden);
  }

  getOrderTrackingForStaff(id_orden: number): Promise<unknown> {
    return this.ordersService.getOrderTrackingForStaff(id_orden);
  }

  updateShipment(
    id_orden: number,
    dto: UpdateShipmentDto,
    cambiado_por: number,
  ): Promise<unknown> {
    return this.ordersService.updateShipment(id_orden, dto, cambiado_por);
  }

  generateDeliveryConfirmationCode(
    id_orden: number,
    generado_por: number,
  ): Promise<unknown> {
    return this.ordersService.generateDeliveryConfirmationCode(
      id_orden,
      generado_por,
    );
  }

  confirmDeliveryByCustomer(
    id_usuario: number,
    id_orden: number,
    codigo: string,
  ): Promise<unknown> {
    return this.ordersService.confirmDeliveryByCustomer(
      id_usuario,
      id_orden,
      codigo,
    );
  }

  createReturnRequest(
    id_usuario: number,
    dto: CreateReturnDto,
  ): Promise<unknown> {
    return this.ordersService.createReturnRequest(id_usuario, dto);
  }

  getUserReturns(id_usuario: number): Promise<unknown[]> {
    return this.ordersService.getUserReturns(id_usuario);
  }

  getAllReturns(): Promise<unknown[]> {
    return this.ordersService.getAllReturns();
  }

  updateReturnStatus(
    id_devolucion: number,
    dto: UpdateReturnStatusDto,
    cambiado_por: number,
  ): Promise<unknown> {
    return this.ordersService.updateReturnStatus(
      id_devolucion,
      dto,
      cambiado_por,
    );
  }

  getProductReviews(id_producto: number): Promise<unknown> {
    return this.reviewsService.getProductReviews(id_producto);
  }

  getReviewEligibility(
    id_usuario: number,
    id_producto: number,
  ): Promise<{
    canReview: boolean;
    hasDeliveredPurchase: boolean;
    hasReview: boolean;
    reason: string | null;
  }> {
    return this.reviewsService.getReviewEligibility(id_usuario, id_producto);
  }

  createReview(
    id_usuario: number,
    dto: CreateReviewDto,
  ): Promise<PublicReview> {
    return this.reviewsService.createReview(id_usuario, dto);
  }

  getAllReviewsAdmin(): Promise<unknown[]> {
    return this.reviewsService.getAllReviewsAdmin();
  }

  getReviewReports(query: ReviewReportsQueryDto): Promise<ReviewReportPage> {
    return this.reviewModerationService.getReviewReports(query);
  }

  getReviewModeration(id: number): Promise<ReviewModerationDetail> {
    return this.reviewModerationService.getReviewModeration(id);
  }

  moderateReview(
    id: number,
    actorId: number,
    dto: ModerateReviewDto,
  ): Promise<ReviewModerationDetail> {
    return this.reviewModerationService.moderateReview(id, actorId, dto);
  }

  getCart(id_usuario: number): Promise<unknown> {
    return this.cartService.getCart(id_usuario);
  }

  addCartItem(id_usuario: number, dto: AddCartItemDto): Promise<unknown> {
    return this.cartService.addItem(id_usuario, dto);
  }

  updateCartItem(
    id_usuario: number,
    id_variante: number,
    dto: UpdateCartItemDto,
  ): Promise<unknown> {
    return this.cartService.updateItem(id_usuario, id_variante, dto);
  }

  removeCartItem(id_usuario: number, id_variante: number): Promise<unknown> {
    return this.cartService.removeItem(id_usuario, id_variante);
  }

  clearCart(id_usuario: number): Promise<unknown> {
    return this.cartService.clearCart(id_usuario);
  }

  getCheckoutSummary(
    id_usuario: number,
    codigo_promocion?: string,
    id_metodo_envio?: number,
  ): Promise<unknown> {
    return this.checkoutService.getCheckoutSummary(
      id_usuario,
      codigo_promocion,
      id_metodo_envio,
    );
  }

  lookupPostalCode(codigoPostal: string): Promise<unknown> {
    return this.checkoutService.lookupPostalCode(codigoPostal);
  }

  getUserPaymentMethods(id_usuario: number): Promise<unknown[]> {
    return this.checkoutService.getUserPaymentMethods(id_usuario);
  }

  createUserPaymentMethod(
    id_usuario: number,
    dto: CheckoutCardDto,
  ): Promise<unknown> {
    return this.checkoutService.createUserPaymentMethod(id_usuario, dto);
  }

  deleteUserPaymentMethod(
    id_usuario: number,
    id_metodo_pago: number,
  ): Promise<unknown> {
    return this.checkoutService.deleteUserPaymentMethod(
      id_usuario,
      id_metodo_pago,
    );
  }

  confirmCheckout(
    id_usuario: number,
    dto: CreateCheckoutOrderDto,
  ): Promise<unknown> {
    return this.checkoutService.confirmCheckout(id_usuario, dto);
  }

  processMercadoPagoWebhook(
    body: unknown,
    query: Record<string, unknown>,
  ): Promise<unknown> {
    return this.checkoutService.processMercadoPagoWebhook(body, query);
  }

  getPromotions(admin = false): Promise<unknown[]> {
    return this.promotionsService.getPromotions(admin);
  }

  getOfferProducts(): Promise<unknown[]> {
    return this.promotionsService.getOfferProducts();
  }

  createPromotion(dto: CreatePromotionDto, userId: number): Promise<unknown> {
    return this.promotionsService.createPromotion(dto, userId);
  }

  updatePromotion(
    id: number,
    dto: UpdatePromotionDto,
    userId: number,
  ): Promise<unknown> {
    return this.promotionsService.updatePromotion(id, dto, userId);
  }

  getShippingMethods(admin = false): Promise<unknown[]> {
    return this.promotionsService.getShippingMethods(admin);
  }

  updateShippingMethod(
    id: number,
    dto: UpdateShippingMethodDto,
  ): Promise<unknown> {
    return this.promotionsService.updateShippingMethod(id, dto);
  }
}
