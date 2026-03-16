export interface ExcelRow {
  sku: string;
  tipo: string;
  cantidad: number;
  costo_unitario?: number;
  referencia_tipo?: string;
  referencia_id?: number;
}

export class ExcelImportResult {
  success: number;
  errors: Array<{
    row: number;
    sku: string;
    error: string;
    data: any;
  }>;
  total: number;
}
