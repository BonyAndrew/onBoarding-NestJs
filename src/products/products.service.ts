import { Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Products } from "./entities/product.entity";
import { Repository } from "typeorm";
import { CreateProductDto } from "./dto/create-product.dto";
import { updateProductDto } from "./dto/update-product.dto";

@Injectable()
export class ProductsService {
  constructor(
    @InjectRepository(Products)
    private productsRepository: Repository<Products>,
  ) { }

  findAll(): Promise<Products[]> {
    return this.productsRepository.find();
  }

  findOne(id): Promise<Products> {
    return this.productsRepository.findOneBy(id);
  }

  async remove(id: string): Promise<void> {
    await this.productsRepository.delete(id);
  }

  async create(createProductDto: CreateProductDto): Promise<Products> {
    const product = new Products();
    product.name = createProductDto.name;
    product.description = createProductDto.description;
    product.color = createProductDto.color;
    return this.productsRepository.save(product);
  }

  async update(id: number, updateProductDto: updateProductDto) {
    const product = await this.findOne(id);
    console.log(product);

    if (!product) {
      throw new NotFoundException();
    }

    Object.assign(product, updateProductDto);

    return await this.productsRepository.save(product);
  }//✅
}
