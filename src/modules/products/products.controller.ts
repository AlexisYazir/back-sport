import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  HttpCode,
  HttpStatus,
  Put,
  Delete,
  UseGuards,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  ParseFilePipe,
  ParseIntPipe,
  Req,
  Query,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { ProductsService } from './products.service';

import { CreateProductDto } from './dto/product/create-product.dto';
import { CreateProductSportsDto } from './dto/product/create-product-sports.dto';
import { CreateAttributeDto } from './dto/product/create-attribute.dto';
import { CreateVarAttributeValuesDto } from './dto/product/create-var-att_vls.dto';
import { CreateProductVariantDto } from './dto/product/create-product_variant.dto';
import { UpdateProductInvDto } from './dto/product/update-product-inv.dto';
import { UpdateProductFullDto } from './dto/product/update-product-full.dto';
import { UpdateProductVariantAttributeDto } from './dto/product/update.product-var-attr.dto';

import { CreateCategorieDto } from './dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from './dto/categories/update-categorie.dto';

import { CreateMarcaDto } from './dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from './dto/marca/update-marca.dto';
import { Roles } from '../../services/auth/roles.decorator';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../services/auth/roles.guard';

import { CreateInventoryMovementDto } from './dto/inventory/create-inventory_movement.dto';
import { CreateInventoryMovementSkuDto } from './dto/inventory/create-inventory-movement-sku.dto';
import { UpdateOrderStatusDto } from './dto/orders/update-order-status.dto';
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
import { CreateReviewDto } from './dto/reviews/create-review.dto';
import { AddCartItemDto } from './dto/cart/add-cart-item.dto';
import { UpdateCartItemDto } from './dto/cart/update-cart-item.dto';
import {
  CheckoutCardDto,
  CreateCheckoutOrderDto,
} from './dto/checkout/create-checkout-order.dto';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  //* Funciones para productos
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-product')
  async createProduct(@Body() createProductDto: CreateProductDto) {
    return this.productsService.createProduct(createProductDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('assign-product-sports')
  async assignProductSports(@Body() dto: CreateProductSportsDto) {
    return this.productsService.assignProductSports(dto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('upload-image')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: {
        files: 1,
        fileSize: 2 * 1024 * 1024,
        fields: 5,
      },
      fileFilter: (_req, file, callback) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];

        if (!allowedMimeTypes.includes(file.mimetype)) {
          return callback(
            new BadRequestException(
              'Solo se permiten imágenes JPG, PNG o WEBP',
            ),
            false,
          );
        }

        callback(null, true);
      },
    }),
  )
  async uploadImage(
    @UploadedFile(
      new ParseFilePipe({
        validators: [],
        fileIsRequired: true,
        exceptionFactory: () =>
          new BadRequestException('Debe enviar una imagen válida'),
      }),
    )
    file: Express.Multer.File,
    @Body('folder') folder?: string,
  ) {
    if (!file) {
      throw new BadRequestException('No se recibió ningún archivo');
    }

    const allowedFolders = ['products', 'categories', 'temp'];
    if (folder && !allowedFolders.includes(folder)) {
      throw new BadRequestException('Carpeta no permitida');
    }

    return this.productsService.uploadImage(file, folder);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-product-variant')
  async createProductVariant(
    @Body() createProductVariantDto: CreateProductVariantDto,
  ) {
    return this.productsService.createProductVariant(createProductVariantDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-variant-attribute-values')
  async createVariantAttributeValue(
    @Body() createVarAttributeValuesDto: CreateVarAttributeValuesDto,
  ) {
    return this.productsService.createVariantAttributeValue(
      createVarAttributeValuesDto,
    );
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-inventory-movement')
  async createInventoryMovement(
    @Body() createInventoryMovementDto: CreateInventoryMovementDto,
  ) {
    return this.productsService.createInventoryMovement(
      createInventoryMovementDto,
    );
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('inventory-movements/bulk')
  async bulkCreateInventoryMovements(
    @Body() body: { movements: CreateInventoryMovementSkuDto[] },
  ) {
    return this.productsService.bulkCreateInventoryMovements(body.movements);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('inventory-movements')
  async getInventoryMovements() {
    return this.productsService.getInventoryMovements();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('inventory-movements/variants')
  async getVariantsForInventoryMovement() {
    return this.productsService.getVariantsForInventoryMovement();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-attribute')
  async createAttribute(@Body() createAttributeDto: CreateAttributeDto) {
    console.log(createAttributeDto);
    return this.productsService.createAttribute(createAttributeDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-product-inventory')
  async updateProductInventory(
    @Body() updateProductInvDto: UpdateProductInvDto,
  ) {
    return this.productsService.updateProductInv(updateProductInvDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-product-full')
  @HttpCode(HttpStatus.OK)
  async updateProductFull(@Body() dto: UpdateProductFullDto) {
    const result = await this.productsService.updateProductFull(dto);

    return {
      message: 'Producto base actualizado correctamente',
      data: result,
    };
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-product-variant')
  @HttpCode(HttpStatus.OK)
  async updateProductVariant(@Body() dto: UpdateProductVariantAttributeDto) {
    const result = await this.productsService.updateProductVariant(dto);

    return {
      message:
        'Datos de producto: variante y atributos actualizados correctamente',
      data: result,
    };
  }

  @Get('get-all-products')
  async getAllProducts() {
    return this.productsService.getAllProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('get-all-orders')
  async getAllOrders() {
    return this.productsService.getAllOrders();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('get-order-details/:id')
  async getOrderDetail(@Param('id') id: string) {
    return this.productsService.getOrderDetail(Number(id));
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('orders/employee')
  async getEmployeeOrders() {
    return this.productsService.getEmployeeOrders();
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('orders/user')
  async getUserOrders(@Req() req: any) {
    return this.productsService.getUserOrders(req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Put('orders/:id/status')
  async updateOrderStatus(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateOrderStatusDto,
  ) {
    return this.productsService.updateOrderStatus(
      id,
      dto.estado,
      req.user.id_usuario,
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('orders/:id/tracking')
  async getOrderTracking(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
  ) {
    return this.productsService.getOrderTracking(req.user.id_usuario, id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('orders/:id/tracking/staff')
  async getOrderTrackingForStaff(@Param('id', ParseIntPipe) id: number) {
    return this.productsService.getOrderTrackingForStaff(id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Put('orders/:id/shipment')
  async updateShipment(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateShipmentDto,
  ) {
    return this.productsService.updateShipment(id, dto, req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('returns')
  async createReturnRequest(@Req() req: any, @Body() dto: CreateReturnDto) {
    return this.productsService.createReturnRequest(req.user.id_usuario, dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('returns/user')
  async getUserReturns(@Req() req: any) {
    return this.productsService.getUserReturns(req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('returns/admin')
  async getAllReturns() {
    return this.productsService.getAllReturns();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Put('returns/:id/status')
  async updateReturnStatus(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateReturnStatusDto,
  ) {
    return this.productsService.updateReturnStatus(
      id,
      dto,
      req.user.id_usuario,
    );
  }

  @Get('promotions/public')
  async getPublicPromotions() {
    return this.productsService.getPromotions(false);
  }

  @Get('promotions/offers')
  async getOfferProducts() {
    return this.productsService.getOfferProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('promotions/admin')
  async getAdminPromotions() {
    return this.productsService.getPromotions(true);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('promotions')
  async createPromotion(@Req() req: any, @Body() dto: CreatePromotionDto) {
    return this.productsService.createPromotion(dto, req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('promotions/:id')
  async updatePromotion(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdatePromotionDto,
  ) {
    return this.productsService.updatePromotion(id, dto, req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('shipping-methods/admin')
  async getAdminShippingMethods() {
    return this.productsService.getShippingMethods(true);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('shipping-methods/:id')
  async updateShippingMethod(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateShippingMethodDto,
  ) {
    return this.productsService.updateShippingMethod(id, dto);
  }

  @Get('get-product-details/:id')
  async getProductDetail(@Param('id') id: number) {
    return this.productsService.getProductDetail(+id);
  }

  @Get('reviews/product/:id')
  async getProductReviews(@Param('id', ParseIntPipe) id: number) {
    return this.productsService.getProductReviews(id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('reviews/product/:id/eligibility')
  async getReviewEligibility(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
  ) {
    return this.productsService.getReviewEligibility(req.user.id_usuario, id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('reviews/admin/all')
  async getAllReviewsAdmin() {
    return this.productsService.getAllReviewsAdmin();
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('reviews')
  async createReview(@Req() req: any, @Body() dto: CreateReviewDto) {
    return this.productsService.createReview(req.user.id_usuario, dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('cart')
  async getCart(@Req() req: any) {
    return this.productsService.getCart(req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('cart/items')
  async addCartItem(@Req() req: any, @Body() dto: AddCartItemDto) {
    return this.productsService.addCartItem(req.user.id_usuario, dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Put('cart/items/:idVariante')
  async updateCartItem(
    @Req() req: any,
    @Param('idVariante', ParseIntPipe) idVariante: number,
    @Body() dto: UpdateCartItemDto,
  ) {
    return this.productsService.updateCartItem(
      req.user.id_usuario,
      idVariante,
      dto,
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('cart/items/:idVariante')
  async removeCartItem(
    @Req() req: any,
    @Param('idVariante', ParseIntPipe) idVariante: number,
  ) {
    return this.productsService.removeCartItem(req.user.id_usuario, idVariante);
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('cart')
  async clearCart(@Req() req: any) {
    return this.productsService.clearCart(req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('checkout/summary')
  async getCheckoutSummary(
    @Req() req: any,
    @Query('codigo_promocion') codigoPromocion?: string,
    @Query('id_metodo_envio') idMetodoEnvio?: string,
  ) {
    return this.productsService.getCheckoutSummary(
      req.user.id_usuario,
      codigoPromocion,
      idMetodoEnvio ? Number(idMetodoEnvio) : undefined,
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('checkout/postal-code/:codigoPostal')
  async lookupPostalCode(@Param('codigoPostal') codigoPostal: string) {
    return this.productsService.lookupPostalCode(codigoPostal);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('checkout/confirm')
  async confirmCheckout(
    @Req() req: any,
    @Body() dto: CreateCheckoutOrderDto,
  ) {
    return this.productsService.confirmCheckout(req.user.id_usuario, dto);
  }

  @Post('checkout/mercado-pago/webhook')
  async mercadoPagoWebhook(@Body() body: any, @Query() query: any) {
    return this.productsService.processMercadoPagoWebhook(body, query);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('payment-methods')
  async getUserPaymentMethods(@Req() req: any) {
    return this.productsService.getUserPaymentMethods(req.user.id_usuario);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('payment-methods')
  async createUserPaymentMethod(
    @Req() req: any,
    @Body() dto: CheckoutCardDto,
  ) {
    return this.productsService.createUserPaymentMethod(
      req.user.id_usuario,
      dto,
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('payment-methods/:idMetodoPago')
  async deleteUserPaymentMethod(
    @Req() req: any,
    @Param('idMetodoPago', ParseIntPipe) idMetodoPago: number,
  ) {
    return this.productsService.deleteUserPaymentMethod(
      req.user.id_usuario,
      idMetodoPago,
    );
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-inventory-products')
  async getInventoryProducts() {
    return this.productsService.getInventoryProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-recient-products')
  async getRecientProducts() {
    return this.productsService.getRecientProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-variants-by-product/:id')
  async getVariantsByProduct(@Param('id') id: number) {
    return this.productsService.getVariantsByProduct(+id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-products-without-variants-attributes')
  async getProductsWithoutVariantsAttributes() {
    return this.productsService.getProductsWithoutVariantsAttributes();
  }

  //* Funciones para marcas
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-marca')
  async createMarca(@Body() createMarcaDto: CreateMarcaDto) {
    return this.productsService.createMarca(createMarcaDto);
  }

  @Get('get-all-marcas')
  async getMarcas() {
    return this.productsService.getMarcas();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('update-marca')
  async updateMarca(@Body() updateMarcaDto: UpdateMarcaDto) {
    return this.productsService.updateMarca(updateMarcaDto);
  }

  //* Funciones para categorias
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-categorie')
  async createCategorie(@Body() createCategorieDto: CreateCategorieDto) {
    return this.productsService.createCategory(createCategorieDto);
  }

  @Get('get-all-categories')
  async getCategories() {
    return this.productsService.getCategories();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-categorie')
  async updateCategorie(@Body() updateCategorieDto: UpdateCategorieDto) {
    return this.productsService.updateCategory(updateCategorieDto);
  }

  //* Funciones para atributos
  @Get('get-all-attributes')
  async getAttributes() {
    return this.productsService.getAttributes();
  }

  //* Funciones para ordenes
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('get-all-orders')
  async getOrdersEmployee() {
    return this.productsService.getOrderss();
  }

  //* PARA EL MENU
  @Get('menu/categories-by-parent/:parentId')
  async getCategoriesByParent(@Param('parentId') parentId: number) {
    return this.productsService.getCategoriesByParent(+parentId);
  }

  @Get('menu/sports')
  async getSports() {
    return this.productsService.getSports();
  }

  @Get('menu/brands')
  async getBrands() {
    return this.productsService.getMarcas();
  }

  @Get('menu/complete-menu')
  async getCompleteMenu() {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return this.productsService.getCompleteMenu();
  }
}
