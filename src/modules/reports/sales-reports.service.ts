import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

type Granularity = 'day' | 'week' | 'month';

interface ReportQuery {
  from?: string;
  to?: string;
  granularity?: string;
}

interface ReportRange {
  from: string;
  to: string;
  previousFrom: string;
  previousTo: string;
  granularity: Granularity;
  days: number;
}

interface NumericSummary {
  grossSales: number;
  netSales: number;
  orders: number;
  averageTicket: number;
  customers: number;
  repeatCustomers: number;
  repeatCustomerRate: number;
  units: number;
  discounts: number;
  shippingRevenue: number;
  refundAmount: number;
  returnRequests: number;
  refundedReturns: number;
  returnRate: number;
}

@Injectable()
export class SalesReportsService {
  private readonly timeZone = 'America/Mexico_City';
  private readonly datePattern = /^\d{4}-\d{2}-\d{2}$/;

  constructor(
    @InjectDataSource('adminConnection')
    private readonly adminDataSource: DataSource,
  ) {}

  async getSalesReport(query: ReportQuery): Promise<any> {
    const range = this.resolveRange(query);

    const [
      currentSales,
      previousSales,
      currentReturns,
      previousReturns,
      trend,
      topProducts,
      categories,
      orderStatuses,
      promotions,
      returnStatuses,
      topCustomers,
    ] = await Promise.all([
      this.getSalesSummary(range.from, range.to),
      this.getSalesSummary(range.previousFrom, range.previousTo),
      this.getReturnsSummary(range.from, range.to),
      this.getReturnsSummary(range.previousFrom, range.previousTo),
      this.getSalesTrend(range),
      this.getTopProducts(range.from, range.to),
      this.getCategoryPerformance(range.from, range.to),
      this.getOrderStatusDistribution(range.from, range.to),
      this.getPromotionPerformance(range.from, range.to),
      this.getReturnStatusDistribution(range.from, range.to),
      this.getTopCustomers(range.from, range.to),
    ]);

    const summary = this.normalizeSummary(currentSales, currentReturns);
    const previousSummary = this.normalizeSummary(previousSales, previousReturns);
    const normalizedProducts = topProducts.map((row) => ({
      idProduct: this.toNumber(row.id_producto),
      name: row.nombre,
      category: row.categoria || 'Sin categoría',
      brand: row.marca || 'Sin marca',
      image: row.imagen || null,
      units: this.toNumber(row.unidades),
      orders: this.toNumber(row.pedidos),
      revenue: this.toNumber(row.ingresos),
      contribution: summary.grossSales > 0
        ? this.round((this.toNumber(row.ingresos) / summary.grossSales) * 100)
        : 0,
    }));

    const result = {
      meta: {
        from: range.from,
        to: range.to,
        previousFrom: range.previousFrom,
        previousTo: range.previousTo,
        granularity: range.granularity,
        days: range.days,
        generatedAt: new Date().toISOString(),
        currency: 'MXN',
        timeZone: this.timeZone,
      },
      summary,
      comparison: {
        previous: previousSummary,
        netSalesChange: this.percentageChange(summary.netSales, previousSummary.netSales),
        grossSalesChange: this.percentageChange(summary.grossSales, previousSummary.grossSales),
        ordersChange: this.percentageChange(summary.orders, previousSummary.orders),
        averageTicketChange: this.percentageChange(
          summary.averageTicket,
          previousSummary.averageTicket,
        ),
        customersChange: this.percentageChange(summary.customers, previousSummary.customers),
      },
      trend: trend.map((row) => ({
        period: row.periodo,
        grossSales: this.toNumber(row.ventas_brutas),
        netSales: this.round(
          this.toNumber(row.ventas_brutas) - this.toNumber(row.reembolsos),
        ),
        refunds: this.toNumber(row.reembolsos),
        discounts: this.toNumber(row.descuentos),
        orders: this.toNumber(row.pedidos),
        units: this.toNumber(row.unidades),
      })),
      topProducts: normalizedProducts,
      categories: categories.map((row) => ({
        category: row.categoria || 'Sin categoría',
        units: this.toNumber(row.unidades),
        orders: this.toNumber(row.pedidos),
        revenue: this.toNumber(row.ingresos),
        contribution: summary.grossSales > 0
          ? this.round((this.toNumber(row.ingresos) / summary.grossSales) * 100)
          : 0,
      })),
      orderStatuses: orderStatuses.map((row) => ({
        status: row.estado || 'sin_estado',
        orders: this.toNumber(row.pedidos),
        amount: this.toNumber(row.monto),
      })),
      promotions: promotions.map((row) => ({
        idPromotion: this.toNumber(row.id_promocion),
        name: row.nombre,
        code: row.codigo || null,
        uses: this.toNumber(row.usos),
        customers: this.toNumber(row.clientes),
        discount: this.toNumber(row.descuento_aplicado),
        associatedRevenue: this.toNumber(row.ventas_asociadas),
      })),
      returnStatuses: returnStatuses.map((row) => ({
        status: row.estado || 'sin_estado',
        requests: this.toNumber(row.solicitudes),
        amount: this.toNumber(row.monto),
      })),
      topCustomers: topCustomers.map((row) => ({
        idUser: this.toNumber(row.id_usuario),
        name: row.cliente || 'Cliente',
        email: row.email,
        orders: this.toNumber(row.pedidos),
        units: this.toNumber(row.unidades),
        total: this.toNumber(row.total),
        averageTicket: this.toNumber(row.ticket_promedio),
      })),
    };

    return {
      ...result,
      insights: this.buildInsights(result),
    };
  }

  private async getSalesSummary(from: string, to: string): Promise<any> {
    const rows = await this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden)
          p.id_orden,
          p.estado,
          p.proveedor_pago
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      ),
      paid_orders AS (
        SELECT o.*
        FROM core.orders o
        INNER JOIN latest_payment lp
          ON lp.id_orden = o.id_orden
         AND LOWER(TRIM(lp.estado)) = 'aprobado'
        WHERE o.fecha_pago IS NOT NULL
          AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
      ),
      order_units AS (
        SELECT oi.id_orden, COALESCE(SUM(oi.cantidad), 0)::int AS unidades
        FROM core.order_items oi
        INNER JOIN paid_orders po ON po.id_orden = oi.id_orden
        GROUP BY oi.id_orden
      ),
      shipping AS (
        SELECT s.id_orden, COALESCE(MAX(s.costo_envio), 0) AS costo_envio
        FROM core.shipments s
        INNER JOIN paid_orders po ON po.id_orden = s.id_orden
        GROUP BY s.id_orden
      ),
      customer_orders AS (
        SELECT id_usuario, COUNT(*)::int AS pedidos
        FROM paid_orders
        GROUP BY id_usuario
      )
      SELECT
        COALESCE(SUM(po.total), 0) AS ventas_brutas,
        COUNT(po.id_orden)::int AS pedidos,
        COUNT(DISTINCT po.id_usuario)::int AS clientes,
        COALESCE(SUM(ou.unidades), 0)::int AS unidades,
        COALESCE(SUM(po.descuento), 0) AS descuentos,
        COALESCE(SUM(sh.costo_envio), 0) AS ingresos_envio,
        COALESCE(AVG(po.total), 0) AS ticket_promedio,
        COALESCE((SELECT COUNT(*) FROM customer_orders WHERE pedidos > 1), 0)::int
          AS clientes_recurrentes
      FROM paid_orders po
      LEFT JOIN order_units ou ON ou.id_orden = po.id_orden
      LEFT JOIN shipping sh ON sh.id_orden = po.id_orden;
      `,
      [from, to],
    );

    return rows[0] || {};
  }

  private async getReturnsSummary(from: string, to: string): Promise<any> {
    const rows = await this.adminDataSource.query(
      `
      WITH return_totals AS (
        SELECT
          r.id_devolucion,
          r.estado,
          r.solicitado_en,
          r.resuelto_en,
          COALESCE(SUM(ri.total), 0) AS total
        FROM core.returns r
        LEFT JOIN core.return_items ri
          ON ri.id_devolucion = r.id_devolucion
        GROUP BY r.id_devolucion
      )
      SELECT
        COUNT(*) FILTER (
          WHERE (((solicitado_en AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
        )::int AS solicitudes,
        COUNT(*) FILTER (
          WHERE estado = 'reembolsada'
            AND (((resuelto_en AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
              BETWEEN $1::date AND $2::date)
        )::int AS devoluciones_reembolsadas,
        COALESCE(SUM(total) FILTER (
          WHERE estado = 'reembolsada'
            AND (((resuelto_en AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
              BETWEEN $1::date AND $2::date)
        ), 0) AS monto_reembolsado
      FROM return_totals;
      `,
      [from, to],
    );

    return rows[0] || {};
  }

  private async getSalesTrend(range: ReportRange): Promise<any[]> {
    const unit = range.granularity === 'day'
      ? 'day'
      : range.granularity === 'week'
        ? 'week'
        : 'month';
    const step = range.granularity === 'day'
      ? '1 day'
      : range.granularity === 'week'
        ? '1 week'
        : '1 month';

    return this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden) p.id_orden, p.estado
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      ),
      paid_orders AS (
        SELECT
          o.*,
          date_trunc(
            '${unit}',
            (o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City'
          ) AS periodo
        FROM core.orders o
        INNER JOIN latest_payment lp
          ON lp.id_orden = o.id_orden
         AND LOWER(TRIM(lp.estado)) = 'aprobado'
        WHERE o.fecha_pago IS NOT NULL
          AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
      ),
      periods AS (
        SELECT generate_series(
          date_trunc('${unit}', $1::date::timestamp),
          date_trunc('${unit}', $2::date::timestamp),
          INTERVAL '${step}'
        ) AS periodo
      ),
      sales AS (
        SELECT
          periodo,
          COALESCE(SUM(total), 0) AS ventas_brutas,
          COALESCE(SUM(descuento), 0) AS descuentos,
          COUNT(*)::int AS pedidos
        FROM paid_orders
        GROUP BY periodo
      ),
      units AS (
        SELECT po.periodo, COALESCE(SUM(oi.cantidad), 0)::int AS unidades
        FROM paid_orders po
        INNER JOIN core.order_items oi ON oi.id_orden = po.id_orden
        GROUP BY po.periodo
      ),
      refunds AS (
        SELECT
          date_trunc(
            '${unit}',
            (r.resuelto_en AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City'
          ) AS periodo,
          COALESCE(SUM(ri.total), 0) AS reembolsos
        FROM core.returns r
        INNER JOIN core.return_items ri ON ri.id_devolucion = r.id_devolucion
        WHERE r.estado = 'reembolsada'
          AND r.resuelto_en IS NOT NULL
          AND (((r.resuelto_en AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
        GROUP BY 1
      )
      SELECT
        TO_CHAR(p.periodo, 'YYYY-MM-DD') AS periodo,
        COALESCE(s.ventas_brutas, 0) AS ventas_brutas,
        COALESCE(s.descuentos, 0) AS descuentos,
        COALESCE(s.pedidos, 0)::int AS pedidos,
        COALESCE(u.unidades, 0)::int AS unidades,
        COALESCE(r.reembolsos, 0) AS reembolsos
      FROM periods p
      LEFT JOIN sales s ON s.periodo = p.periodo
      LEFT JOIN units u ON u.periodo = p.periodo
      LEFT JOIN refunds r ON r.periodo = p.periodo
      ORDER BY p.periodo;
      `,
      [range.from, range.to],
    );
  }

  private async getTopProducts(from: string, to: string): Promise<any[]> {
    return this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden) p.id_orden, p.estado
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      ),
      paid_orders AS (
        SELECT o.id_orden
        FROM core.orders o
        INNER JOIN latest_payment lp
          ON lp.id_orden = o.id_orden
         AND LOWER(TRIM(lp.estado)) = 'aprobado'
        WHERE o.fecha_pago IS NOT NULL
          AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
      )
      SELECT
        p.id_producto,
        COALESCE(MAX(oi.nombre_producto), p.nombre) AS nombre,
        c.nombre AS categoria,
        m.nombre AS marca,
        MAX(pv.imagenes->>0) AS imagen,
        COALESCE(SUM(oi.cantidad), 0)::int AS unidades,
        COUNT(DISTINCT oi.id_orden)::int AS pedidos,
        COALESCE(SUM(oi.total), 0) AS ingresos
      FROM paid_orders po
      INNER JOIN core.order_items oi ON oi.id_orden = po.id_orden
      INNER JOIN core.product_variants pv ON pv.id_variante = oi.id_variante
      INNER JOIN core.products p ON p.id_producto = pv.id_producto
      LEFT JOIN core.categories c ON c.id_categoria = p.id_categoria
      LEFT JOIN core.marcas m ON m.id_marca = p.id_marca
      GROUP BY p.id_producto, p.nombre, c.nombre, m.nombre
      ORDER BY ingresos DESC, unidades DESC, p.id_producto
      LIMIT 10;
      `,
      [from, to],
    );
  }

  private async getCategoryPerformance(from: string, to: string): Promise<any[]> {
    return this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden) p.id_orden, p.estado
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      ),
      paid_orders AS (
        SELECT o.id_orden
        FROM core.orders o
        INNER JOIN latest_payment lp
          ON lp.id_orden = o.id_orden
         AND LOWER(TRIM(lp.estado)) = 'aprobado'
        WHERE o.fecha_pago IS NOT NULL
          AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
      )
      SELECT
        COALESCE(c.nombre, 'Sin categoría') AS categoria,
        COALESCE(SUM(oi.cantidad), 0)::int AS unidades,
        COUNT(DISTINCT oi.id_orden)::int AS pedidos,
        COALESCE(SUM(oi.total), 0) AS ingresos
      FROM paid_orders po
      INNER JOIN core.order_items oi ON oi.id_orden = po.id_orden
      INNER JOIN core.product_variants pv ON pv.id_variante = oi.id_variante
      INNER JOIN core.products p ON p.id_producto = pv.id_producto
      LEFT JOIN core.categories c ON c.id_categoria = p.id_categoria
      GROUP BY c.nombre
      ORDER BY ingresos DESC, unidades DESC;
      `,
      [from, to],
    );
  }

  private async getOrderStatusDistribution(from: string, to: string): Promise<any[]> {
    return this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden) p.id_orden, p.estado
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      )
      SELECT
        LOWER(TRIM(o.estado)) AS estado,
        COUNT(*)::int AS pedidos,
        COALESCE(SUM(o.total), 0) AS monto
      FROM core.orders o
      INNER JOIN latest_payment lp
        ON lp.id_orden = o.id_orden
       AND LOWER(TRIM(lp.estado)) = 'aprobado'
      WHERE o.fecha_pago IS NOT NULL
        AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
          BETWEEN $1::date AND $2::date)
      GROUP BY LOWER(TRIM(o.estado))
      ORDER BY pedidos DESC, estado;
      `,
      [from, to],
    );
  }

  private async getPromotionPerformance(from: string, to: string): Promise<any[]> {
    return this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden) p.id_orden, p.estado
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      ),
      paid_orders AS (
        SELECT o.id_orden, o.id_usuario, o.total
        FROM core.orders o
        INNER JOIN latest_payment lp
          ON lp.id_orden = o.id_orden
         AND LOWER(TRIM(lp.estado)) = 'aprobado'
        WHERE o.fecha_pago IS NOT NULL
          AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
      )
      SELECT
        p.id_promocion,
        p.nombre,
        p.codigo,
        COUNT(DISTINCT pr.id_orden)::int AS usos,
        COUNT(DISTINCT pr.id_usuario)::int AS clientes,
        COALESCE(SUM(pr.descuento_aplicado), 0) AS descuento_aplicado,
        COALESCE(SUM(po.total), 0) AS ventas_asociadas
      FROM core.promotion_redemptions pr
      INNER JOIN paid_orders po ON po.id_orden = pr.id_orden
      INNER JOIN core.promotions p ON p.id_promocion = pr.id_promocion
      GROUP BY p.id_promocion, p.nombre, p.codigo
      ORDER BY ventas_asociadas DESC, usos DESC
      LIMIT 8;
      `,
      [from, to],
    );
  }

  private async getReturnStatusDistribution(from: string, to: string): Promise<any[]> {
    return this.adminDataSource.query(
      `
      SELECT
        LOWER(TRIM(r.estado)) AS estado,
        COUNT(DISTINCT r.id_devolucion)::int AS solicitudes,
        COALESCE(SUM(ri.total), 0) AS monto
      FROM core.returns r
      LEFT JOIN core.return_items ri ON ri.id_devolucion = r.id_devolucion
      WHERE (((r.solicitado_en AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
        BETWEEN $1::date AND $2::date)
      GROUP BY LOWER(TRIM(r.estado))
      ORDER BY solicitudes DESC, estado;
      `,
      [from, to],
    );
  }

  private async getTopCustomers(from: string, to: string): Promise<any[]> {
    return this.adminDataSource.query(
      `
      WITH latest_payment AS (
        SELECT DISTINCT ON (p.id_orden) p.id_orden, p.estado
        FROM core.pagos p
        ORDER BY p.id_orden, p.id_pago DESC
      ),
      paid_orders AS (
        SELECT o.*
        FROM core.orders o
        INNER JOIN latest_payment lp
          ON lp.id_orden = o.id_orden
         AND LOWER(TRIM(lp.estado)) = 'aprobado'
        WHERE o.fecha_pago IS NOT NULL
          AND (((o.fecha_pago AT TIME ZONE 'UTC') AT TIME ZONE 'America/Mexico_City')::date
            BETWEEN $1::date AND $2::date)
      ),
      units AS (
        SELECT oi.id_orden, COALESCE(SUM(oi.cantidad), 0)::int AS unidades
        FROM core.order_items oi
        INNER JOIN paid_orders po ON po.id_orden = oi.id_orden
        GROUP BY oi.id_orden
      )
      SELECT
        u.id_usuario,
        COALESCE(
          NULLIF(TRIM(CONCAT_WS(' ', u.nombre, u."aPaterno", u."aMaterno")), ''),
          'Cliente'
        ) AS cliente,
        u.email,
        COUNT(po.id_orden)::int AS pedidos,
        COALESCE(SUM(un.unidades), 0)::int AS unidades,
        COALESCE(SUM(po.total), 0) AS total,
        COALESCE(AVG(po.total), 0) AS ticket_promedio
      FROM paid_orders po
      INNER JOIN core.users u ON u.id_usuario = po.id_usuario
      LEFT JOIN units un ON un.id_orden = po.id_orden
      GROUP BY u.id_usuario, u.nombre, u."aPaterno", u."aMaterno", u.email
      ORDER BY total DESC, pedidos DESC
      LIMIT 8;
      `,
      [from, to],
    );
  }

  private normalizeSummary(sales: any, returns: any): NumericSummary {
    const grossSales = this.toNumber(sales.ventas_brutas);
    const refundAmount = this.toNumber(returns.monto_reembolsado);
    const orders = this.toNumber(sales.pedidos);
    const customers = this.toNumber(sales.clientes);
    const repeatCustomers = this.toNumber(sales.clientes_recurrentes);
    const units = this.toNumber(sales.unidades);

    return {
      grossSales,
      netSales: this.round(Math.max(0, grossSales - refundAmount)),
      orders,
      averageTicket: this.toNumber(sales.ticket_promedio),
      customers,
      repeatCustomers,
      repeatCustomerRate: customers > 0
        ? this.round((repeatCustomers / customers) * 100)
        : 0,
      units,
      discounts: this.toNumber(sales.descuentos),
      shippingRevenue: this.toNumber(sales.ingresos_envio),
      refundAmount,
      returnRequests: this.toNumber(returns.solicitudes),
      refundedReturns: this.toNumber(returns.devoluciones_reembolsadas),
      returnRate: orders > 0
        ? this.round((this.toNumber(returns.devoluciones_reembolsadas) / orders) * 100)
        : 0,
    };
  }

  private buildInsights(report: any): any[] {
    const insights: any[] = [];
    const salesChange = report.comparison.netSalesChange;
    const topProduct = report.topProducts[0];

    if (salesChange === null) {
      insights.push({
        type: 'info',
        icon: 'insights',
        title: 'Primer punto de comparación',
        message: 'El periodo anterior no tuvo ventas netas; este resultado será una nueva referencia.',
      });
    } else if (salesChange >= 5) {
      insights.push({
        type: 'positive',
        icon: 'trending_up',
        title: 'Crecimiento de ventas',
        message: `La venta neta aumentó ${this.formatPercent(Math.abs(salesChange))} frente al periodo anterior.`,
      });
    } else if (salesChange <= -5) {
      insights.push({
        type: 'warning',
        icon: 'trending_down',
        title: 'Ventas por debajo del periodo anterior',
        message: `La venta neta disminuyó ${this.formatPercent(Math.abs(salesChange))}; conviene revisar productos y promociones con menor movimiento.`,
      });
    } else {
      insights.push({
        type: 'info',
        icon: 'horizontal_rule',
        title: 'Ventas estables',
        message: 'La variación frente al periodo anterior se mantiene dentro de un rango de 5%.',
      });
    }

    if (topProduct) {
      insights.push({
        type: topProduct.contribution >= 40 ? 'warning' : 'positive',
        icon: 'workspace_premium',
        title: 'Producto líder del periodo',
        message: `${topProduct.name} aporta ${this.formatPercent(topProduct.contribution)} de las ventas de productos.`,
      });
    }

    if (report.summary.refundAmount > 0) {
      const refundShare = report.summary.grossSales > 0
        ? this.round((report.summary.refundAmount / report.summary.grossSales) * 100)
        : 0;
      insights.push({
        type: refundShare >= 10 ? 'warning' : 'info',
        icon: 'assignment_return',
        title: 'Impacto de reembolsos',
        message: `Los reembolsos equivalen al ${this.formatPercent(refundShare)} de las ventas cobradas del periodo.`,
      });
    } else {
      insights.push({
        type: 'positive',
        icon: 'verified',
        title: 'Sin reembolsos registrados',
        message: 'No hubo importes reembolsados dentro del periodo seleccionado.',
      });
    }

    insights.push({
      type: report.summary.repeatCustomerRate >= 25 ? 'positive' : 'info',
      icon: 'group',
      title: 'Clientes recurrentes',
      message: `${this.formatPercent(report.summary.repeatCustomerRate)} de los clientes compró más de una vez en el periodo.`,
    });

    return insights.slice(0, 4);
  }

  private resolveRange(query: ReportQuery): ReportRange {
    let to = query.to;
    let from = query.from;

    if (!from && !to) {
      to = this.getMexicoToday();
      from = this.addDays(to, -29);
    } else if (!from || !to) {
      throw new BadRequestException('Debes indicar la fecha inicial y final');
    }

    this.validateDate(from);
    this.validateDate(to);

    const days = this.daysBetween(from, to) + 1;
    if (days <= 0) {
      throw new BadRequestException('La fecha inicial debe ser menor o igual a la final');
    }
    if (days > 731) {
      throw new BadRequestException('El periodo máximo permitido es de 24 meses');
    }

    const allowedGranularities: Granularity[] = ['day', 'week', 'month'];
    const automaticGranularity: Granularity = days <= 45
      ? 'day'
      : days <= 180
        ? 'week'
        : 'month';
    const granularity = query.granularity as Granularity | undefined;

    if (granularity && !allowedGranularities.includes(granularity)) {
      throw new BadRequestException('La agrupación seleccionada no es válida');
    }

    const previousTo = this.addDays(from, -1);
    const previousFrom = this.addDays(previousTo, -(days - 1));

    return {
      from,
      to,
      previousFrom,
      previousTo,
      granularity: granularity || automaticGranularity,
      days,
    };
  }

  private validateDate(value: string): void {
    if (!this.datePattern.test(value)) {
      throw new BadRequestException('Las fechas deben usar el formato AAAA-MM-DD');
    }

    const date = new Date(`${value}T00:00:00.000Z`);
    if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) {
      throw new BadRequestException('La fecha indicada no es válida');
    }
  }

  private getMexicoToday(): string {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: this.timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(new Date());
  }

  private addDays(value: string, amount: number): string {
    const date = new Date(`${value}T00:00:00.000Z`);
    date.setUTCDate(date.getUTCDate() + amount);
    return date.toISOString().slice(0, 10);
  }

  private daysBetween(from: string, to: string): number {
    const fromTime = new Date(`${from}T00:00:00.000Z`).getTime();
    const toTime = new Date(`${to}T00:00:00.000Z`).getTime();
    return Math.floor((toTime - fromTime) / 86400000);
  }

  private percentageChange(current: number, previous: number): number | null {
    if (previous === 0) {
      return current === 0 ? 0 : null;
    }
    return this.round(((current - previous) / previous) * 100);
  }

  private toNumber(value: unknown): number {
    const number = Number(value || 0);
    return Number.isFinite(number) ? this.round(number) : 0;
  }

  private round(value: number): number {
    return Math.round((Number(value || 0) + Number.EPSILON) * 100) / 100;
  }

  private formatPercent(value: number): string {
    return `${this.round(value).toLocaleString('es-MX', { maximumFractionDigits: 1 })}%`;
  }
}
