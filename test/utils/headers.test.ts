import {
  prepareHeadersForIngressAPI,
  getAgentUri,
  getResultUri,
  getStatusUri,
  filterRequestHeaders,
  updateResponseHeaders,
} from '../../src/utils/headers'
import { CloudFrontRequest, CloudFrontHeaders } from 'aws-lambda'
import { IncomingHttpHeaders } from 'http'

describe('test fpjs-headers preparation', () => {
  test('verify existing values', () => {
    const req: CloudFrontRequest = {
      clientIp: '1.1.1.1',
      method: 'GET',
      uri: 'fpjs/agent',
      querystring: 'apiKey=ujKG34hUYKLJKJ1F&version=3&loaderVersion=3.6.2',
      headers: {},
      origin: {
        custom: {
          domainName: 'adewe.cloudfront.net',
          keepaliveTimeout: 60,
          path: '/',
          port: 443,
          protocol: 'https',
          readTimeout: 60,
          sslProtocols: ['TLSv2'],
          customHeaders: {
            fpjs_pre_shared_secret: [
              {
                key: 'fpjs_pre_shared_secret',
                value: 'qwertyuio1356767',
              },
            ],
          },
        },
      },
    }
    const headers = prepareHeadersForIngressAPI(req)
    expect(headers['fpjs-client-ip']).toBe('1.1.1.1')
    expect(headers['fpjs-proxy-identification']).toBe('qwertyuio1356767')
  })

  test('secret is not defined', () => {
    const req: CloudFrontRequest = {
      clientIp: '1.1.1.1',
      method: 'GET',
      uri: 'fpjs/agent',
      querystring: 'apiKey=ujKG34hUYKLJKJ1F&version=3&loaderVersion=3.6.2',
      headers: {},
      origin: {
        custom: {
          domainName: 'adewe.cloudfront.net',
          keepaliveTimeout: 60,
          path: '/',
          port: 443,
          protocol: 'https',
          readTimeout: 60,
          sslProtocols: ['TLSv2'],
          customHeaders: {},
        },
      },
    }
    const headers = prepareHeadersForIngressAPI(req)
    expect(headers['fpjs-client-ip']).toBe('1.1.1.1')
    expect(headers['fpjs-proxy-identification']).toBe('secret-is-not-defined')
  })
})

describe('test custom headers', () => {
  test('positive scenario for custom origin', () => {
    const req: CloudFrontRequest = {
      clientIp: '1.1.1.1',
      method: 'GET',
      uri: 'fpjs/agent',
      querystring: 'apiKey=ujKG34hUYKLJKJ1F&version=3&loaderVersion=3.6.2',
      headers: {},
      origin: {
        custom: {
          domainName: 'adewe.cloudfront.net',
          keepaliveTimeout: 60,
          path: '/',
          port: 443,
          protocol: 'https',
          readTimeout: 60,
          sslProtocols: ['TLSv2'],
          customHeaders: {
            fpjs_pre_shared_secret: [
              {
                key: 'fpjs_pre_shared_secret',
                value: 'qwertyuio1356767',
              },
            ],
            fpjs_agent_download_path: [
              {
                key: 'fpjs_agent_download_path',
                value: 'greiodsfkljlds',
              },
            ],
            fpjs_behavior_path: [
              {
                key: 'fpjs_behavior_path',
                value: 'eifjdsnmzxcn',
              },
            ],
            fpjs_get_result_path: [
              {
                key: 'fpjs_get_result_path',
                value: 'eiwflsdkadlsjdsa',
              },
            ],
          },
        },
      },
    }

    expect(getAgentUri(req)).toBe('/eifjdsnmzxcn/greiodsfkljlds')
    expect(getResultUri(req)).toBe('/eifjdsnmzxcn/eiwflsdkadlsjdsa')
    expect(getStatusUri(req)).toBe('/eifjdsnmzxcn/status')
  })

  test('positive scenario for s3 origin', () => {
    const req: CloudFrontRequest = {
      clientIp: '1.1.1.1',
      method: 'GET',
      uri: 'fpjs/agent',
      querystring: 'apiKey=ujKG34hUYKLJKJ1F&version=3&loaderVersion=3.6.2',
      headers: {},
      origin: {
        s3: {
          domainName: 'adewe.cloudfront.net',
          path: '/',
          region: 'us',
          authMethod: 'none',
          customHeaders: {
            fpjs_pre_shared_secret: [
              {
                key: 'fpjs_pre_shared_secret',
                value: 'qwertyuio1356767',
              },
            ],
            fpjs_agent_download_path: [
              {
                key: 'fpjs_agent_download_path',
                value: 'greiodsfkljlds',
              },
            ],
            fpjs_behavior_path: [
              {
                key: 'fpjs_behavior_path',
                value: 'eifjdsnmzxcn',
              },
            ],
            fpjs_get_result_path: [
              {
                key: 'fpjs_get_result_path',
                value: 'eiwflsdkadlsjdsa',
              },
            ],
          },
        },
      },
    }

    expect(getAgentUri(req)).toBe('/eifjdsnmzxcn/greiodsfkljlds')
    expect(getResultUri(req)).toBe('/eifjdsnmzxcn/eiwflsdkadlsjdsa')
    expect(getStatusUri(req)).toBe('/eifjdsnmzxcn/status')
  })

  test('no headers', () => {
    const req: CloudFrontRequest = {
      clientIp: '1.1.1.1',
      method: 'GET',
      uri: 'fpjs/agent',
      querystring: 'apiKey=ujKG34hUYKLJKJ1F&version=3&loaderVersion=3.6.2',
      headers: {},
      origin: {
        custom: {
          domainName: 'adewe.cloudfront.net',
          keepaliveTimeout: 60,
          path: '/',
          port: 443,
          protocol: 'https',
          readTimeout: 60,
          sslProtocols: ['TLSv2'],
          customHeaders: {},
        },
      },
    }

    expect(getAgentUri(req)).toBe('/fpjs/agent')
    expect(getResultUri(req)).toBe('/fpjs/resultId')
    expect(getStatusUri(req)).toBe('/fpjs/status')
  })
})

describe('filterRequestHeaders', () => {
  test('test filtering blackilisted headers', () => {
    const req: CloudFrontRequest = {
      clientIp: '1.1.1.1',
      method: 'GET',
      uri: 'fpjs/agent',
      querystring: 'apiKey=ujKG34hUYKLJKJ1F&version=3&loaderVersion=3.6.2',
      headers: {
        'content-type': [
          {
            key: 'content-type',
            value: 'application/json',
          },
        ],
        'content-length': [
          {
            key: 'content-length',
            value: '24354',
          },
        ],
        host: [
          {
            key: 'host',
            value: 'fpjs.sh',
          },
        ],
        'transfer-encoding': [
          {
            key: 'transfer-encoding',
            value: 'br',
          },
        ],
        via: [
          {
            key: 'via',
            value: 'cloudfront.net',
          },
        ],
        cookie: [
          {
            key: 'cookie',
            value: '_iidt,rGjGpiWkgQ,,;_iidt=7A03Gwg==;_vid_t=gEFRuIQlzYmv692/UL4GLA==',
          },
        ],
      },
    }
    const headers = filterRequestHeaders(req)

    expect(headers.hasOwnProperty('content-length')).toBe(false)
    expect(headers.hasOwnProperty('host')).toBe(false)
    expect(headers.hasOwnProperty('transfer-encoding')).toBe(false)
    expect(headers.hasOwnProperty('via')).toBe(false)
    expect(headers['content-type']).toBe('application/json')
    expect(headers['cookie']).toBe('_iidt,rGjGpiWkgQ,,; _iidt=7A03Gwg==; _vid_t=gEFRuIQlzYmv692/UL4GLA==')
  })
})

describe('updateResponseHeaders', () => {
  test('test', () => {
    const headers: IncomingHttpHeaders = {
      'access-control-allow-credentials': 'true',
      'access-control-allow-origin': 'true',
      'access-control-expose-headers': 'true',
      'cache-control': 'public, max-age=40000, s-maxage=40000',
      'content-encoding': 'br',
      'content-length': '73892',
      'content-type': 'application/json',
      'cross-origin-resource-policy': 'cross-origin',
      etag: 'dskjhfadsjk',
      'set-cookie': ['_iidf', 'HttpOnly', 'Domain=cloudfront.net'],
      vary: 'Accept-Encoding',
      'custom-header-1': 'gdfddfd',
    }
    const cfHeaders: CloudFrontHeaders = updateResponseHeaders(headers, 'fpjs.sh')
    expect(cfHeaders.hasOwnProperty('custom-header-1')).toBe(false)
    expect(cfHeaders.hasOwnProperty('content-length')).toBe(false)
    expect(cfHeaders['cache-control'][0].value).toBe('public, max-age=3600, s-maxage=40000')
    expect(cfHeaders['set-cookie'][0].value).toBe('_iidf; HttpOnly; Domain=fpjs.sh')
  })

  test('update cache policy', () => {
    const headers: IncomingHttpHeaders = {
      'access-control-allow-credentials': 'true',
      'access-control-allow-origin': 'true',
      'access-control-expose-headers': 'true',
      'cache-control': 'no-cache',
      'content-encoding': 'br',
      'content-length': '73892',
      'content-type': 'application/json',
      'cross-origin-resource-policy': 'cross-origin',
      etag: 'dskjhfadsjk',
      'set-cookie': ['_iidf', 'HttpOnly', 'Domain=cloudfront.net'],
      vary: 'Accept-Encoding',
      'custom-header-1': 'gdfddfd',
    }
    const cfHeaders: CloudFrontHeaders = updateResponseHeaders(headers, 'fpjs.sh')
    expect(cfHeaders.hasOwnProperty('custom-header-1')).toBe(false)
    expect(cfHeaders.hasOwnProperty('content-length')).toBe(false)
    expect(cfHeaders['cache-control'][0].value).toBe('no-cache, max-age=3600')
    expect(cfHeaders['set-cookie'][0].value).toBe('_iidf; HttpOnly; Domain=fpjs.sh')
  })
})
