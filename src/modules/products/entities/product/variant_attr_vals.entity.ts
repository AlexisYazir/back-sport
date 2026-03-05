import { Entity, Column, PrimaryColumn } from 'typeorm';

@Entity('core.variant_attribute_values')
export class VariantAttributeValue {
  @PrimaryColumn()
  id_variante: number;

  @PrimaryColumn()
  id_atributo: number;

  @Column({ length: 100 })
  valor: string;
}
