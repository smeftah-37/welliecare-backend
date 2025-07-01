import { Controller, Get, Param, Res } from "@nestjs/common";
import { Response } from 'express';
import { join } from 'path';
import * as fs from 'fs';

@Controller('uploads')
export class PicturesController {
  @Get(':filename')
  getPicture(@Param('filename') filename: string, @Res() res: Response) {
    const filePath = join(process.cwd(), 'uploads', filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File not found' });
    }

    res.sendFile(filePath);
  }
}