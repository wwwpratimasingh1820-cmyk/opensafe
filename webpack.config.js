const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const CompressionPlugin = require('compression-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = (env, argv) => {
  const isProduction = argv.mode === 'production';

  return {
    entry: './src/app.js',
    output: {
      filename: isProduction ? 'app.[contenthash].js' : '[name].bundle.js',
      path: path.resolve(__dirname, 'dist'),
      clean: true,
    },
    devtool: isProduction ? false : 'source-map',
    module: {
      rules: [
        {
          test: /\.js$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
          },
        },
        {
          test: /\.css$/,
          use: [
            MiniCssExtractPlugin.loader,
            'css-loader',
          ],
        },
        {
          test: /\.(png|svg|jpg|jpeg|gif)$/i,
          type: 'asset/resource',
        },
      ],
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: './src/index.html',
        minify: isProduction ? {
          removeComments: true,
          collapseWhitespace: true,
          removeRedundantAttributes: true,
        } : false,
      }),
      new MiniCssExtractPlugin({
        filename: isProduction ? 'styles.[contenthash].css' : 'styles.css',
      }),
      new CopyWebpackPlugin({
        patterns: [
          { from: 'src/assets', to: 'assets' },
          { from: 'src/data', to: 'data' },
          { from: 'manifest.json', to: 'manifest.json' },
          { from: 'ads.txt', to: 'ads.txt' },
        ],
      }),
      ...(isProduction ? [
        new CompressionPlugin({
          algorithm: 'brotliCompress',
          test: /\.(js|css|html|svg)$/,
          threshold: 10240,
          minRatio: 0.8,
        }),
      ] : []),
    ],
    devServer: {
      static: './dist',
      hot: true,
      port: 3000,
      open: true,
    },
    optimization: {
      usedExports: true,
      splitChunks: {
        chunks: 'all',
      },
    },
    performance: {
      maxEntrypointSize: 3000000, // 3MB
      maxAssetSize: 3000000,
    },
  };
};
