import * as fpjs from '@fingerprintjs/fingerprintjs-pro'

type Text = string | { html: string }

async function getVisitorData() {
  const agent = await fpjs.load({
    apiKey: process.env.API_KEY as string,
    endpoint: process.env.ENDPOINT,
    scriptUrlPattern: process.env.SCRIPT_URL_PATTERN,
  })

  return await agent.get({
    extendedResult: true,
  })
}

async function getAndPrintData() {
  const output = document.querySelector('.output')
  if (!output) {
    throw new Error("The output element isn't found in the HTML code")
  }

  const startTime = Date.now()

  try {
    const response = await getVisitorData()
    const { visitorId, confidence } = response

    console.log('Got response', response)

    const totalTime = Date.now() - startTime
    output.innerHTML = ''
    addOutputSection({ output, header: 'Visitor identifier:', content: visitorId, size: 'giant' })
    addOutputSection({ output, header: 'Time took to get the identifier:', content: `${totalTime}ms`, size: 'big' })
    addOutputSection({
      output,
      header: 'Confidence score:',
      content: String(confidence.score),
      comment: confidence.comment
        ? {
            html: confidence.comment.replace(
              /(upgrade\s+to\s+)?pro(\s+version)?(:\s+(https?:\/\/\S+))?/gi,
              '<a href="$4" target="_blank">$&</a>',
            ),
          }
        : '',
      size: 'big',
    })
    addOutputSection({ output, header: 'User agent:', content: navigator.userAgent })

    initializeDebugButtons(`Visitor identifier: \`${visitorId}\`
Time took to get the identifier: ${totalTime}ms
Confidence: ${JSON.stringify(confidence)}
User agent: \`${navigator.userAgent}\`
\`\`\`
\`\`\``)
  } catch (error) {
    const totalTime = Date.now() - startTime
    const errorData = error instanceof Error ? error.message : JSON.stringify(error)
    output.innerHTML = ''
    addOutputSection({ output, header: 'Unexpected error:', content: JSON.stringify(errorData, null, 2) })
    addOutputSection({ output, header: 'Time passed before the error:', content: `${totalTime}ms`, size: 'big' })
    addOutputSection({ output, header: 'User agent:', content: navigator.userAgent })

    initializeDebugButtons(`Unexpected error:\n
\`\`\`
${JSON.stringify(errorData, null, 2)}
\`\`\`
Time passed before the error: ${totalTime}ms
User agent: \`${navigator.userAgent}\``)
    throw error
  }
}

async function startPlayground() {
  const getDataButton = document.querySelector('#getData')
  if (getDataButton instanceof HTMLButtonElement) {
    getDataButton.disabled = false
    getDataButton.addEventListener('click', async (event) => {
      event.preventDefault()

      await getAndPrintData()
    })
  }
}

function addOutputSection({
  output,
  header,
  content,
  comment,
  size,
}: {
  output: Node
  header: Text
  content: Text
  comment?: Text
  size?: 'big' | 'giant'
}) {
  const headerElement = document.createElement('div')
  headerElement.appendChild(textToDOM(header))
  headerElement.classList.add('heading')
  output.appendChild(headerElement)

  const contentElement = document.createElement('pre')
  contentElement.appendChild(textToDOM(content))
  if (size) {
    contentElement.classList.add(size)
  }
  output.appendChild(contentElement)

  if (comment) {
    const commentElement = document.createElement('div')
    commentElement.appendChild(textToDOM(comment))
    commentElement.classList.add('comment')
    output.appendChild(commentElement)
  }
}

function initializeDebugButtons(debugText: string) {
  const copyButton = document.querySelector('#debugCopy')
  if (copyButton instanceof HTMLButtonElement) {
    copyButton.disabled = false
    copyButton.addEventListener('click', (event) => {
      event.preventDefault()
      copy(debugText)
    })
  }
}

function copy(text: string) {
  const textarea = document.createElement('textarea')
  textarea.value = text
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  try {
    document.execCommand('copy')
  } catch {
    // Do nothing in case of a copying error
  }
  document.body.removeChild(textarea)
}

function textToDOM(text: Text): Node {
  if (typeof text === 'string') {
    return document.createTextNode(text)
  }
  const container = document.createElement('div')
  container.innerHTML = text.html
  const fragment = document.createDocumentFragment()
  while (container.firstChild) {
    fragment.appendChild(container.firstChild)
  }
  return fragment
}

startPlayground()
