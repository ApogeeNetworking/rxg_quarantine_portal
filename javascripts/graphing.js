function generateLineChart(name, meta, data) {
  const {
    start: usageStartTime,
    end: usageEndTime,
    step,
    legend
  } = meta
  const duration = usageEndTime - usageStartTime
  const steps = duration / step
  const labels = []
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  for (let i = 0; i < steps; i++) {
    const date = new Date((usageStartTime + step * i) * 1000)
    labels.push(days[date.getDay()])
  }
  return {
    name,
    labels,
    series: [{

        data: data.map((value, index) => {
          return {
            x: index,
            y: value[0] / 1000
          }
        })
      },
      {

        data: data.map((value, index) => {
          return {
            x: index,
            y: value[1] / 1000
          }
        })
      }
    ]
  }
}

function generateBarChart(name, data) {
  return {
    name,
    labels: data.map(value => value.x),
    series: [{
      data: data.map((value, index) => {
        var {
          y
        } = value
        return {
          x: index,
          y
        }
      })
    }]
  }
}


function generateGraph(name, meta, data, isBarChart) {
  return isBarChart ? generateBarChart(name, data) : generateLineChart(name, meta, data)
}

function initGraph(json, container, options = {}) {
  const {
    name,
    groupBy,
    isBarChart,
    id,
    graphTime
  } = options
  const values = isBarChart ? json[0].values : json.data
  const meta = json.meta
  const data = generateGraph(name, meta, values, isBarChart)

  const chartOptions = {
    low: 0,
    showArea: true,
    showPoint: false,
    chartPadding: 0,
    axisX: {
      labelInterpolationFnc: (value, index, labels) => {
        let interpolated = 0
        let threshold = 0
        switch (groupBy) {
          case 'second':
          case 'minute':
            threshold = 12
            interpolated = 180
            break
          case 'hour':
            threshold = 24
            interpolated = 24
            break
          case 'day':
            threshold = 30
            interpolated = 7
            break
          default:
            break
        }
        if (labels.length > threshold) {
          return index % interpolated === 0 ? value : null
        }
        return value
      }
    },
    axisY: {
      onlyInteger: true,
      labelOffset: {
        y: 12
      },
    }
  }

  if (!isBarChart) {
    chartOptions.axisY.labelInterpolationFnc = function(value, index, arr) {
      return index == 0 ? '0' : index >= arr.length - 1 ? `${(value / 1000).toFixed(0)} Mb` : null
    }
  }

  return {
    graph: isBarChart ?
    new Chartist.Bar(container, data, chartOptions) : new Chartist.Line(container, data, chartOptions),
    name,
    raw: {
      meta,
      data
    },
    isEmpty: data.series[0].data.filter(({x, y}) => y != 0).length < 1,
    isBarChart,
    graphTime
  }
}
