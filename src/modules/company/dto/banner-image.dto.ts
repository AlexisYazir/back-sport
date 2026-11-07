export interface BannerImageInput {
  url_imagen?: unknown;
  cloudinary_public_id?: unknown;
  titulo?: unknown;
  descripcion?: unknown;
  alt_text?: unknown;
  orden?: unknown;
  activo?: unknown;
}

export interface BannerImage {
  id_banner: number;
  url_imagen: string;
  cloudinary_public_id: string | null;
  titulo: string | null;
  descripcion: string | null;
  alt_text: string | null;
  orden: number;
  activo: boolean;
  creado_por: number | null;
  actualizado_por: number | null;
  fecha_creacion: Date;
  fecha_actualizacion: Date;
}
